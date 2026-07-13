"""ValidationExecutionService — orchestrates the Gated Safe Active
Validation lifecycle end to end (M11).

Mandatory M10 policy gate, TWICE:
  1. At create time: CREATE EXECUTION REQUEST -> NORMALIZE CANONICAL
     TARGET (deferred until after policy ALLOW, since evaluate() only
     needs the target's canonical ID, not its endpoint) -> POLICY
     EVALUATE -> AUDIT DECISION -> only if ALLOW does anything else
     happen.
  2. Immediately before step dispatch (`_reevaluate_before_dispatch`):
     closes the "ALLOW at request time, but the authorization was
     revoked/expired before the (possibly delayed) dispatch actually
     ran" gap. A DENY here transitions an already-AUTHORIZED execution
     straight to DENIED with zero steps ever created.

No adapter in application/validation_execution/network_adapters.py is
ever reachable except through this service — there is no direct
adapter import anywhere in api/v1/validation_executions.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from redforge.application.validation_execution import network_adapters as adapters
from redforge.application.validation_execution.adaptive_rules import (
    DiscoveryFacts,
    default_adaptive_rule_registry,
)
from redforge.application.validation_execution.discovery_enrichment import (
    enrich_discovered_assets,
)
from redforge.application.validation_execution.discovery_port_policy import (
    DISCOVERY_PORT_POLICY_V1,
    expected_service_hint,
    is_sensitive_port,
    sensitive_service_name,
)
from redforge.application.validation_execution.protocol_validators import (
    default_protocol_validator_registry,
)
from redforge.application.validation_execution.step_planner import (
    build_discovery_step_plan,
    build_step_plan,
)
from redforge.application.validation_execution.target_normalizer import normalize_target
from redforge.core.exceptions import ValidationError
from redforge.domain.validation_execution.entity import ValidationExecution, ValidationStep
from redforge.domain.validation_execution.exceptions import (
    TargetNormalizationError,
    ValidationExecutionNotFoundError,
)
from redforge.domain.validation_execution.execution_event import ExecutionEvent
from redforge.domain.validation_execution.value_objects import (
    ErrorCategory,
    ExecutionEventType,
    ExecutionStatus,
    ExecutionTrigger,
    ProtocolValidationState,
    ServiceEvidenceState,
    StepSource,
    StepStatus,
    StepType,
    ValidationProfile,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.ai_targets import AITargetService
    from redforge.application.inventory.tenant_asset_service import TenantAssetService
    from redforge.application.security_conditions.service import TenantSecurityConditionService
    from redforge.application.security_correlation.service import (
        TenantSecurityCorrelationService,
    )
    from redforge.application.validation_execution.adaptive_rules import AdaptiveRuleRegistry
    from redforge.application.validation_execution.contracts import ExecutionPolicyPort
    from redforge.application.validation_execution.network_adapters import SecurityHeaderFinding
    from redforge.application.validation_execution.protocol_validators import (
        ProtocolValidationOutcome,
        ProtocolValidatorRegistry,
    )
    from redforge.application.validation_execution.target_normalizer import NormalizedTarget

_ACTION_CLASS = "active_validation"
_NETWORK_DISCOVERY_SOURCE_CATEGORY = "network_discovery"
_SENSITIVE_SERVICE_RULE_ID = "SENSITIVE_SERVICE_OBSERVED"
_PLAINTEXT_SENSITIVE_SERVICE_RULE_ID = "PLAINTEXT_SENSITIVE_SERVICE_OBSERVED"

# M13 — which candidate protocol name (matching
# discovery_port_policy.DISCOVERY_PORT_HINTS' values and
# ProtocolValidator.supported_protocol) a given closed StepType
# represents. Only these four step types are ever dispatched through
# the ProtocolValidatorRegistry; every other StepType keeps its own
# M11/M12 dispatch branch below unchanged.
_STEP_TYPE_TO_PROTOCOL: dict[StepType, str] = {
    StepType.SSH_BANNER: "ssh",
    StepType.MYSQL_HANDSHAKE: "mysql",
    StepType.POSTGRESQL_HANDSHAKE: "postgresql",
    StepType.REDIS_PING: "redis",
}

# Deterministic severity per M13 condition stable_rule_id — generalizes
# the single X_CONTENT_TYPE_OPTIONS special-case _ingest_condition() had
# before M13 added TLS-derived findings with their own severities.
_CONDITION_SEVERITY: dict[str, str] = {
    "MISSING_X_CONTENT_TYPE_OPTIONS_HEADER": "low",
    "TLS_CERTIFICATE_EXPIRED": "high",
    "TLS_SELF_SIGNED_CERTIFICATE_OBSERVED": "medium",
    "DEPRECATED_TLS_PROTOCOL_OBSERVED": "medium",
}


def _ev(label: str, value: object) -> dict[str, str]:
    """Build one bounded evidence entry. `truncated` is always "false"
    here — every value passed in this module is already a short,
    bounded scalar (a status code, a hostname, a fingerprint), never an
    arbitrary-length response body."""
    return {"label": label, "value": "" if value is None else str(value), "truncated": "false"}


def _parse_tcp_port_fact_ref(fact_ref: str | None) -> int | None:
    """Parses the `"tcp_port:{port}:reachable"` fact_ref shape every
    adaptive rule (M12 HTTP/TLS, M13 protocol candidates) uses. Returns
    None for anything that doesn't match — callers fall back to a safe
    default rather than crashing."""
    if not fact_ref:
        return None
    parts = fact_ref.split(":")
    if len(parts) != 3 or parts[0] != "tcp_port":
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


# ─── DTOs ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class StepDTO:
    id: str
    step_type: str
    order: int
    status: str
    started_at: str | None
    completed_at: str | None
    evidence: list[dict[str, str]]
    error_category: str | None
    source: str = "initial"
    adaptive_rule_id: str | None = None
    adaptive_rule_version: int | None = None
    source_fact_ref: str | None = None
    validator_id: str | None = None
    validator_version: int | None = None
    protocol_validation_state: str | None = None


@dataclass(frozen=True, slots=True)
class ValidationExecutionDTO:
    id: str
    organization_id: str
    target_id: str
    requester_user_id: str
    profile: str
    status: str
    policy_decision_id: str | None
    policy_reason_code: str | None
    cancellation_requested: bool
    created_at: str
    updated_at: str
    started_at: str | None
    completed_at: str | None
    failure_reason: str
    trigger: str = "manual"
    continuous_policy_id: str | None = None
    scheduled_due_at: str | None = None
    steps: list[StepDTO] = field(default_factory=list)

    @classmethod
    def from_entity(cls, execution: ValidationExecution) -> ValidationExecutionDTO:
        return cls(
            id=str(execution.id),
            organization_id=str(execution.organization_id),
            target_id=str(execution.target_id),
            requester_user_id=str(execution.requester_user_id),
            profile=str(execution.profile),
            status=str(execution.status),
            policy_decision_id=execution.policy_decision_id,
            policy_reason_code=execution.policy_reason_code,
            cancellation_requested=execution.cancellation_requested,
            created_at=execution.timestamps.created_at.isoformat(),
            updated_at=execution.timestamps.updated_at.isoformat(),
            started_at=execution.started_at.isoformat() if execution.started_at else None,
            completed_at=execution.completed_at.isoformat() if execution.completed_at else None,
            failure_reason=execution.failure_reason,
            trigger=str(execution.trigger),
            continuous_policy_id=(
                str(execution.continuous_policy_id) if execution.continuous_policy_id else None
            ),
            scheduled_due_at=(
                execution.scheduled_due_at.isoformat() if execution.scheduled_due_at else None
            ),
            steps=[
                StepDTO(
                    id=str(s.id), step_type=str(s.step_type), order=s.order, status=str(s.status),
                    started_at=s.started_at.isoformat() if s.started_at else None,
                    completed_at=s.completed_at.isoformat() if s.completed_at else None,
                    evidence=list(s.evidence),
                    error_category=str(s.error_category) if s.error_category else None,
                    source=str(s.source), adaptive_rule_id=s.adaptive_rule_id,
                    adaptive_rule_version=s.adaptive_rule_version,
                    source_fact_ref=s.source_fact_ref,
                    validator_id=s.validator_id, validator_version=s.validator_version,
                    protocol_validation_state=s.protocol_validation_state,
                )
                for s in execution.steps
            ],
        )


@dataclass(frozen=True, slots=True)
class EventDTO:
    id: str
    execution_id: str
    sequence: int
    event_type: str
    payload: dict[str, str]
    occurred_at: str

    @classmethod
    def from_entity(cls, event: ExecutionEvent) -> EventDTO:
        return cls(
            id=str(event.id), execution_id=str(event.execution_id), sequence=event.sequence,
            event_type=str(event.event_type), payload=event.payload,
            occurred_at=event.occurred_at.isoformat(),
        )


# ─── Service ──────────────────────────────────────────────────────────────


class ValidationExecutionService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        execution_policy_service: ExecutionPolicyPort,
        ai_target_service: AITargetService,
        tenant_asset_service: TenantAssetService,
        security_condition_service: TenantSecurityConditionService,
        adaptive_rule_registry: AdaptiveRuleRegistry | None = None,
        correlation_service: TenantSecurityCorrelationService | None = None,
        protocol_validator_registry: ProtocolValidatorRegistry | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._execution_policy_service = execution_policy_service
        self._ai_target_service = ai_target_service
        self._tenant_asset_service = tenant_asset_service
        self._security_condition_service = security_condition_service
        # Both optional, matching M6's own TenantNetworkDiscoveryService
        # precedent (condition_service: ... | None = None) — M12's
        # adaptive planning and correlation re-evaluation degrade
        # gracefully (never block or corrupt execution truth) rather
        # than requiring every caller/test to wire them.
        self._adaptive_rule_registry = adaptive_rule_registry or default_adaptive_rule_registry()
        self._correlation_service = correlation_service
        self._protocol_validator_registry = (
            protocol_validator_registry or default_protocol_validator_registry()
        )

    # ─── Create + run ───────────────────────────────────────────────────

    async def create_and_run(
        self,
        organization_id: str,
        target_id: str,
        requester_user_id: str,
        profile: str = "safe_active_baseline_v1",
        trigger: ExecutionTrigger = ExecutionTrigger.MANUAL,
        continuous_policy_id: str | None = None,
        scheduled_due_at: datetime | None = None,
    ) -> ValidationExecutionDTO:
        """`trigger`/`continuous_policy_id`/`scheduled_due_at` are never
        client-supplied — every M11-M13 caller (the public REST API)
        uses the defaults (MANUAL, unset). Only the M14 continuous-
        validation processor (an internal, server-only caller) ever
        passes non-default values, and it does so from its own
        already-claimed, already-computed due-boundary truth — never
        from a request body field."""
        try:
            parsed_profile = ValidationProfile(profile)
        except ValueError as exc:
            raise ValidationError(f"Unknown validation profile: {profile!r}") from exc

        execution = ValidationExecution.create(
            organization_id=EntityId.from_string(organization_id),
            target_id=EntityId.from_string(target_id),
            requester_user_id=EntityId.from_string(requester_user_id),
            profile=parsed_profile,
            trigger=trigger,
            continuous_policy_id=(
                EntityId.from_string(continuous_policy_id) if continuous_policy_id else None
            ),
            scheduled_due_at=scheduled_due_at,
        )
        await self._save(execution)
        await self._emit(execution, ExecutionEventType.EXECUTION_CREATED, {"target_id": target_id})

        execution.begin_policy_check()
        await self._save(execution)
        await self._emit(execution, ExecutionEventType.POLICY_CHECK_STARTED, {})

        decision = await self._execution_policy_service.evaluate(
            organization_id=organization_id,
            actor_user_id=requester_user_id,
            action_class=_ACTION_CLASS,
            entity_refs=[("ai_target", target_id)],
        )

        if decision.decision != "allow":
            execution.deny(decision.decision_id, decision.reason_code)
            await self._save(execution)
            await self._emit(
                execution, ExecutionEventType.POLICY_DENIED,
                {"reason_code": decision.reason_code, "decision_id": decision.decision_id},
            )
            return ValidationExecutionDTO.from_entity(execution)

        execution.authorize(decision.decision_id)
        await self._save(execution)
        await self._emit(
            execution, ExecutionEventType.POLICY_ALLOWED, {"decision_id": decision.decision_id},
        )

        # Second, mandatory time-of-use check immediately before dispatch —
        # closes the ALLOW-then-revoked-before-dispatch gap.
        redecision = await self._execution_policy_service.evaluate(
            organization_id=organization_id,
            actor_user_id=requester_user_id,
            action_class=_ACTION_CLASS,
            entity_refs=[("ai_target", target_id)],
        )
        if redecision.decision != "allow":
            execution.deny(redecision.decision_id, redecision.reason_code)
            await self._save(execution)
            await self._emit(
                execution, ExecutionEventType.POLICY_DENIED,
                {
                    "reason_code": redecision.reason_code,
                    "decision_id": redecision.decision_id,
                    "stage": "pre_dispatch",
                },
            )
            return ValidationExecutionDTO.from_entity(execution)

        # Resolve the canonical target's endpoint and build the plan.
        try:
            target_dto = await self._get_ai_target(organization_id, target_id)
            normalized = normalize_target(target_dto["endpoint"])
        except TargetNormalizationError as exc:
            execution.fail_preflight(f"target normalization failed: {exc.message}")
            await self._save(execution)
            await self._emit(
                execution, ExecutionEventType.EXECUTION_FAILED,
                {"reason": "target_normalization_failed"},
            )
            return ValidationExecutionDTO.from_entity(execution)

        step_types = (
            build_discovery_step_plan(normalized)
            if parsed_profile == ValidationProfile.NETWORK_DISCOVERY_BASELINE_V1
            else build_step_plan(normalized)
        )
        execution.build_plan(step_types)
        await self._save(execution)
        await self._emit(
            execution, ExecutionEventType.PLAN_CREATED, {"step_count": str(len(execution.steps))},
        )

        execution.start()
        await self._save(execution)
        await self._emit(execution, ExecutionEventType.EXECUTION_STARTED, {})

        asset_id = await self._get_or_create_asset(organization_id, target_id, target_dto)

        await self._run_steps(execution, normalized, organization_id, asset_id)

        return ValidationExecutionDTO.from_entity(execution)

    async def _run_steps(
        self,
        execution: ValidationExecution,
        target: NormalizedTarget,
        organization_id: str,
        asset_id: str,
    ) -> None:
        limits = execution.limits
        resolved_addresses: tuple[str, ...] = ()
        tcp_reachable = False
        http_ok = False
        tls_ok = False
        hard_stop = False
        last_http_headers: dict[str, str] = {}
        service_asset_by_port: dict[int, str] = {}
        conditions_ingested = 0

        i = 0
        # Index-based, not `for step in list(execution.steps)`: adaptive
        # rule evaluation appends new steps to `execution.steps`
        # mid-loop (see the PORT_DISCOVERY branch below), and `.steps`
        # returns a fresh tuple snapshot on every access — a
        # pre-captured list would never see them.
        while i < len(execution.steps):
            step = execution.steps[i]
            i += 1
            if hard_stop:
                step.skip()
                continue

            # Cancellation check — fresh read, before every step dispatch.
            if await self._is_cancellation_requested(organization_id, str(execution.id)):
                execution.cancel()
                await self._save(execution)
                await self._emit(execution, ExecutionEventType.EXECUTION_CANCELLED, {})
                return

            # The canonical, ONE dispatch boundary every adaptively
            # scheduled step must cross before any network I/O — never
            # called from inside a low-level adapter. Closes the
            # "authorization revoked after discovery, before the
            # adaptively-added step actually dispatches" gap, the same
            # way M11's own double-gate closes it for the initial plan.
            if step.source == StepSource.ADAPTIVE and not await self._adaptive_dispatch_allowed(
                execution, organization_id,
            ):
                step.start(utc_now())
                step.fail(utc_now(), ErrorCategory.POLICY_DENIED)
                await self._save(execution)
                await self._emit(
                    execution, ExecutionEventType.STEP_FAILED,
                    {"step_type": str(step.step_type), "reason": "policy_denied"},
                )
                hard_stop = True
                continue

            effective_target = self._effective_target_for_step(target, step)

            step.start(utc_now())
            await self._save(execution)
            await self._emit(
                execution, ExecutionEventType.STEP_STARTED, {"step_type": str(step.step_type)},
            )

            if step.step_type == StepType.PORT_DISCOVERY:
                await self._emit(execution, ExecutionEventType.DISCOVERY_STARTED, {
                    "port_count": str(len(DISCOVERY_PORT_POLICY_V1)),
                })
                discovery = await adapters.discover_ports(
                    resolved_addresses, DISCOVERY_PORT_POLICY_V1,
                    limits.per_step_timeout_seconds, limits.max_concurrency,
                )
                reachable_ports = discovery.reachable_ports
                evidence = tuple(
                    _ev(f"port_{port}", (
                        f"{discovery.best_outcome_for_port(port).value}:"
                        f"{expected_service_hint(port) or 'unknown'}"
                    ))
                    for port in DISCOVERY_PORT_POLICY_V1
                )
                step.complete(utc_now(), evidence)
                await self._emit(
                    execution, ExecutionEventType.PORT_REACHABILITY_OBSERVED,
                    {"reachable_ports": ",".join(str(p) for p in reachable_ports)},
                )

                if resolved_addresses:
                    enrichment = await enrich_discovered_assets(
                        self._tenant_asset_service, organization_id, str(execution.target_id),
                        asset_id, resolved_addresses, reachable_ports,
                    )
                    service_asset_by_port = {
                        s.port: s.service_asset_id for s in enrichment.services
                    }
                    await self._emit(execution, ExecutionEventType.ASSET_RESOLVED, {
                        "ip_count": str(len(enrichment.ip_asset_ids)),
                        "host_resolved": str(enrichment.host_asset_id is not None),
                        "service_count": str(len(enrichment.services)),
                    })
                    for port, service_asset_id in service_asset_by_port.items():
                        # Discovery alone never validates a protocol —
                        # only an adaptively-dispatched TLS/HTTP step
                        # can later prove SERVICE_VALIDATED for this
                        # exact port (see the HTTP_METADATA/
                        # TLS_HANDSHAKE branches below).
                        state = (
                            ServiceEvidenceState.SERVICE_HINTED
                            if expected_service_hint(port)
                            else ServiceEvidenceState.PORT_REACHABLE
                        )
                        await self._emit(execution, ExecutionEventType.SERVICE_CONTEXT_UPDATED, {
                            "port": str(port), "service_state": str(state),
                            "hint": expected_service_hint(port) or "unknown",
                        })
                        if is_sensitive_port(port):
                            await self._ingest_sensitive_service_condition(
                                organization_id, service_asset_id, port,
                            )
                            conditions_ingested += 1
                            await self._emit(
                                execution, ExecutionEventType.CONDITION_INGESTED,
                                {"stable_rule_id": _SENSITIVE_SERVICE_RULE_ID, "port": str(port)},
                            )

                    await self._expand_adaptive_plan(
                        execution, reachable_ports, target.is_https,
                    )

            elif step.step_type == StepType.DNS_RESOLUTION:
                dns_result = await adapters.resolve_dns(
                    target.hostname, limits.per_step_timeout_seconds,
                    limits.max_resolved_addresses, limits.dns_retry_attempts,
                )
                if dns_result.ok:
                    resolved_addresses = dns_result.resolved_addresses
                    joined = ",".join(resolved_addresses)
                    step.complete(utc_now(), (_ev("resolved_addresses", joined),))
                else:
                    err = dns_result.error_category or ErrorCategory.NETWORK_BOUNDARY_DENIED
                    evidence = (
                        (_ev("denied_address", dns_result.denied_address),)
                        if dns_result.denied_address else ()
                    )
                    step.fail(utc_now(), err, evidence)
                    hard_stop = True

            elif step.step_type == StepType.TCP_CONNECTIVITY:
                address = resolved_addresses[0] if resolved_addresses else effective_target.hostname
                tcp_result = await adapters.check_tcp_connectivity(
                    address, effective_target.port, limits.per_step_timeout_seconds,
                )
                tcp_reachable = tcp_result.reachable
                if tcp_result.reachable:
                    step.complete(utc_now(), (_ev("latency_ms", tcp_result.latency_ms),))
                else:
                    step.fail(utc_now(), tcp_result.error_category or ErrorCategory.UNKNOWN)
                    hard_stop = True

            elif step.step_type == StepType.TLS_HANDSHAKE:
                address = resolved_addresses[0] if resolved_addresses else effective_target.hostname
                tls_result = await adapters.perform_tls_handshake(
                    address, effective_target.hostname, effective_target.port,
                    limits.per_step_timeout_seconds,
                )
                tls_ok = tls_result.success
                if tls_result.success:
                    tls_findings = adapters.evaluate_tls_findings(tls_result, utc_now().isoformat())
                    step.complete(utc_now(), (
                        _ev("protocol_version", tls_result.protocol_version),
                        _ev("cipher", tls_result.cipher_name),
                        _ev("subject_cn", tls_result.subject_common_name),
                        _ev("not_after", tls_result.not_after),
                        _ev("fingerprint_sha256", tls_result.fingerprint_sha256),
                        *(_ev("rule", f.stable_rule_id) for f in tls_findings),
                    ))
                    await self._mark_service_validated(
                        execution, service_asset_by_port, effective_target.port, "tls",
                    )
                    for finding in tls_findings:
                        await self._ingest_condition(organization_id, asset_id, finding)
                        conditions_ingested += 1
                        await self._emit(
                            execution, ExecutionEventType.CONDITION_INGESTED,
                            {"stable_rule_id": finding.stable_rule_id},
                        )
                else:
                    step.fail(utc_now(), tls_result.error_category or ErrorCategory.TLS_FAILURE)

            elif step.step_type == StepType.HTTP_METADATA:
                http_result = await adapters.fetch_http_metadata(
                    effective_target, resolved_addresses, limits.per_step_timeout_seconds,
                    limits.redirect_limit, limits.per_step_timeout_seconds,
                    limits.dns_retry_attempts,
                )
                http_ok = http_result.success
                if http_result.success:
                    step.complete(utc_now(), (
                        _ev("status_code", http_result.status_code),
                        _ev("content_type", http_result.content_type),
                        _ev("server", http_result.server_header),
                        _ev("final_url", http_result.final_url),
                    ))
                    last_http_headers = http_result.response_headers
                    await self._mark_service_validated(
                        execution, service_asset_by_port, effective_target.port, "http",
                    )
                else:
                    step.fail(utc_now(), http_result.error_category or ErrorCategory.UNKNOWN)
                    last_http_headers = {}

            elif step.step_type == StepType.HTTP_SECURITY_HEADERS:
                findings = adapters.evaluate_security_headers(
                    last_http_headers, effective_target.is_https,
                )
                step.complete(utc_now(), tuple(_ev("rule", f.stable_rule_id) for f in findings))
                for finding in findings:
                    await self._ingest_condition(organization_id, asset_id, finding)
                    await self._emit(
                        execution, ExecutionEventType.CONDITION_INGESTED,
                        {"stable_rule_id": finding.stable_rule_id},
                    )

            elif step.step_type in _STEP_TYPE_TO_PROTOCOL:
                protocol = _STEP_TYPE_TO_PROTOCOL[step.step_type]
                port = _parse_tcp_port_fact_ref(step.source_fact_ref) or effective_target.port
                address = resolved_addresses[0] if resolved_addresses else effective_target.hostname
                validator = self._protocol_validator_registry.get_for_protocol(protocol)
                if validator is None:
                    # Structurally unreachable today (every _STEP_TYPE_TO_PROTOCOL
                    # entry has a registered validator) — defensive only,
                    # never a client-triggerable path.
                    step.fail(utc_now(), ErrorCategory.UNSUPPORTED)
                else:
                    outcome = await validator.validate(
                        address, port, limits.per_step_timeout_seconds,
                    )
                    evidence = (
                        *(_ev(k, v) for k, v in outcome.metadata.items()),
                        _ev("protocol_validation_state", outcome.state.value),
                    )
                    if outcome.state in (
                        ProtocolValidationState.VALIDATED, ProtocolValidationState.INCONCLUSIVE,
                    ):
                        # A completed, bounded read that simply didn't
                        # match the expected protocol shape is a real,
                        # truthful observation — never a step failure.
                        # Port reachable + invalid banner stays HINTED,
                        # never SERVICE_VALIDATED (see _mark_service_validated
                        # below, only called for the VALIDATED branch).
                        step.complete(
                            utc_now(), evidence, validator_id=outcome.validator_id,
                            validator_version=outcome.validator_version,
                            protocol_validation_state=outcome.state.value,
                        )
                    else:
                        step.fail(
                            utc_now(), outcome.error_category or ErrorCategory.UNKNOWN, evidence,
                            validator_id=outcome.validator_id,
                            validator_version=outcome.validator_version,
                            protocol_validation_state=outcome.state.value,
                        )
                    if outcome.state == ProtocolValidationState.VALIDATED:
                        await self._mark_service_validated(
                            execution, service_asset_by_port, port, protocol,
                        )
                        await self._enrich_validated_service(
                            organization_id, service_asset_by_port, port, outcome,
                        )
                        conditions_ingested += await self._ingest_protocol_condition_findings(
                            execution, organization_id, service_asset_by_port, port, protocol,
                            outcome,
                        )

            elif step.step_type == StepType.SERVICE_REACHABILITY:
                validated = tcp_reachable and (http_ok or tls_ok)
                basis = "http" if http_ok else ("tls" if tls_ok else "")
                step.complete(utc_now(), (
                    _ev("tcp_reachable", tcp_reachable),
                    _ev("application_layer_validated", validated),
                    _ev("validation_basis", basis),
                ))

            await self._save(execution)
            event_type = (
                ExecutionEventType.STEP_COMPLETED
                if step.status == StepStatus.COMPLETED
                else ExecutionEventType.STEP_FAILED
            )
            await self._emit(execution, event_type, {"step_type": str(step.step_type)})

        if conditions_ingested > 0:
            await self._evaluate_correlations_best_effort(execution, organization_id)

        final_status = execution.finish()
        await self._save(execution)
        final_event = {
            ExecutionStatus.COMPLETED: ExecutionEventType.EXECUTION_COMPLETED,
            ExecutionStatus.PARTIALLY_COMPLETED: ExecutionEventType.EXECUTION_PARTIAL,
            ExecutionStatus.FAILED: ExecutionEventType.EXECUTION_FAILED,
        }.get(final_status, ExecutionEventType.EXECUTION_FAILED)
        await self._emit(execution, final_event, {})

    # ─── Cancellation ────────────────────────────────────────────────────

    async def cancel(
        self, organization_id: str, execution_id: str, actor_user_id: str,
    ) -> ValidationExecutionDTO:
        from redforge.infrastructure.database.repositories.validation_execution.repository import (
            SqlAlchemyValidationExecutionRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyValidationExecutionRepository(uow.session)
            execution = await repo.get_by_id_for_organization_for_update(
                EntityId.from_string(execution_id), EntityId.from_string(organization_id),
            )
            if execution is None:
                raise ValidationExecutionNotFoundError(execution_id)
            execution.request_cancellation()
            await repo.save(execution)
            await uow.commit()
        await self._emit(execution, ExecutionEventType.CANCELLATION_REQUESTED, {})
        return ValidationExecutionDTO.from_entity(execution)

    async def _is_cancellation_requested(self, organization_id: str, execution_id: str) -> bool:
        from redforge.infrastructure.database.repositories.validation_execution.repository import (
            SqlAlchemyValidationExecutionRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyValidationExecutionRepository(uow.session)
            fresh = await repo.get_by_id_for_organization(
                EntityId.from_string(execution_id), EntityId.from_string(organization_id),
            )
        return fresh is not None and fresh.cancellation_requested

    # ─── Reads ────────────────────────────────────────────────────────────

    async def get_by_id(self, organization_id: str, execution_id: str) -> ValidationExecutionDTO:
        from redforge.infrastructure.database.repositories.validation_execution.repository import (
            SqlAlchemyValidationExecutionRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyValidationExecutionRepository(uow.session)
            execution = await repo.get_by_id_for_organization(
                EntityId.from_string(execution_id), EntityId.from_string(organization_id),
            )
        if execution is None:
            raise ValidationExecutionNotFoundError(execution_id)
        return ValidationExecutionDTO.from_entity(execution)

    async def list_by_organization(
        self, organization_id: str, status: str | None, limit: int, offset: int,
    ) -> list[ValidationExecutionDTO]:
        from redforge.infrastructure.database.repositories.validation_execution.repository import (
            SqlAlchemyValidationExecutionRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        parsed_status = ExecutionStatus(status) if status else None
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyValidationExecutionRepository(uow.session)
            executions = await repo.list_by_organization(
                EntityId.from_string(organization_id), parsed_status, limit, offset,
            )
        return [ValidationExecutionDTO.from_entity(e) for e in executions]

    async def summary(self, organization_id: str) -> dict[str, int]:
        from redforge.infrastructure.database.repositories.validation_execution.repository import (
            SqlAlchemyValidationExecutionRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyValidationExecutionRepository(uow.session)
            raw = await repo.count_by_status(EntityId.from_string(organization_id))
        return {status.value: raw.get(status.value, 0) for status in ExecutionStatus}

    async def list_events(
        self, organization_id: str, execution_id: str, after_sequence: int, limit: int,
    ) -> list[EventDTO]:
        from redforge.infrastructure.database.repositories.validation_execution import (
            event_repository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = event_repository.SqlAlchemyExecutionEventRepository(uow.session)
            events = await repo.list_for_execution(
                EntityId.from_string(execution_id), EntityId.from_string(organization_id),
                after_sequence, limit,
            )
        return [EventDTO.from_entity(e) for e in events]

    # ─── Private helpers ────────────────────────────────────────────────

    async def _save(self, execution: ValidationExecution) -> None:
        from redforge.infrastructure.database.repositories.validation_execution.repository import (
            SqlAlchemyValidationExecutionRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyValidationExecutionRepository(uow.session)
            await repo.save(execution)
            await uow.commit()

    async def _emit(
        self,
        execution: ValidationExecution,
        event_type: ExecutionEventType,
        payload: dict[str, str],
    ) -> None:
        from redforge.infrastructure.database.repositories.validation_execution import (
            event_repository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        if len(payload) > 20:  # defensive bound, payloads here are always small literals
            payload = dict(list(payload.items())[:20])
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = event_repository.SqlAlchemyExecutionEventRepository(uow.session)
            sequence = await repo.next_sequence(execution.id)
            if sequence > execution.limits.max_events:
                await uow.commit()
                return
            event = ExecutionEvent.create(
                execution_id=execution.id, organization_id=execution.organization_id,
                sequence=sequence, event_type=event_type, payload=payload,
            )
            await repo.append(event)
            await uow.commit()

    async def _get_ai_target(self, organization_id: str, target_id: str) -> dict[str, str]:
        dto = await self._ai_target_service.get_by_id(target_id, organization_id)
        return {"endpoint": dto.endpoint, "name": dto.name, "target_type": dto.target_type}

    async def _get_or_create_asset(
        self, organization_id: str, target_id: str, target_dto: dict[str, str],
    ) -> str:
        asset_dto = await self._tenant_asset_service.get_or_create_for_target(
            organization_id=organization_id, target_id=target_id,
            target_name=target_dto["name"], target_type=target_dto["target_type"],
        )
        return str(asset_dto.id)

    async def _ingest_condition(
        self, organization_id: str, asset_id: str, finding: SecurityHeaderFinding,
    ) -> None:
        from redforge.application.security_conditions.ingestion import SecurityConditionInput

        severity = _CONDITION_SEVERITY.get(finding.stable_rule_id, "medium")
        await self._security_condition_service.ingest(SecurityConditionInput(
            organization_id=organization_id,
            affected_asset_id=asset_id,
            source_category="active_validation",
            stable_rule_id=finding.stable_rule_id,
            evidence_state="validated",
            severity=severity,
            title=finding.title,
            summary=finding.summary,
            remediation=finding.remediation,
        ))

    # ─── M12: adaptive plan evolution ──────────────────────────────────

    def _effective_target_for_step(
        self, base_target: NormalizedTarget, step: ValidationStep,
    ) -> NormalizedTarget:
        """For an INITIAL step this is always `base_target` unchanged.
        For an ADAPTIVE step, the port that triggered the rule (encoded
        in `source_fact_ref`, e.g. "tcp_port:443:reachable") overrides
        the scheme/port so the TLS/HTTP adapters actually dispatch
        against the port that was discovered reachable — never the
        target's own original URL port, which may be entirely
        unrelated for NETWORK_DISCOVERY_BASELINE_V1."""
        if step.source != StepSource.ADAPTIVE or not step.source_fact_ref:
            return base_target
        parts = step.source_fact_ref.split(":")
        if len(parts) != 3 or parts[0] != "tcp_port":
            return base_target
        try:
            port = int(parts[1])
        except ValueError:
            return base_target
        scheme = "https" if port in (443, 8443) else "http"
        return replace(base_target, scheme=scheme, port=port)

    async def _adaptive_dispatch_allowed(
        self, execution: ValidationExecution, organization_id: str,
    ) -> bool:
        """The ONE canonical dispatch boundary every adaptively
        scheduled step must cross before any network I/O — never
        called from inside network_adapters.py itself. A fresh
        decision every time, exactly like the two gates
        `create_and_run()` already performs for the initial plan."""
        decision = await self._execution_policy_service.evaluate(
            organization_id=organization_id,
            actor_user_id=str(execution.requester_user_id),
            action_class=_ACTION_CLASS,
            entity_refs=[("ai_target", str(execution.target_id))],
        )
        return decision.decision == "allow"

    async def _expand_adaptive_plan(
        self, execution: ValidationExecution, reachable_ports: tuple[int, ...], is_https: bool,
    ) -> None:
        """Evaluates every registered adaptive rule against the closed
        `DiscoveryFacts` snapshot and appends any resulting steps.
        ADAPTIVE RULES CAN ONLY SELECT PRE-REGISTERED SAFE STEP TYPES —
        `AdaptiveStepSpec.step_type` is a closed `StepType` enum member,
        never a free string. Idempotent: `append_adaptive_step()` itself
        is duplicate- and bound-resistant (see entity.py)."""
        facts = DiscoveryFacts(reachable_ports=frozenset(reachable_ports), target_is_https=is_https)
        for rule in self._adaptive_rule_registry.all_rules():
            existing_step_types = frozenset(s.step_type for s in execution.steps)
            specs = rule.evaluate(facts, existing_step_types)
            for spec in specs:
                added = execution.append_adaptive_step(
                    spec.step_type, rule.rule_id, rule.rule_version, spec.fact_ref,
                )
                if added is None:
                    continue
                await self._save(execution)
                await self._emit(
                    execution, ExecutionEventType.ADAPTIVE_RULE_MATCHED,
                    {"rule_id": rule.rule_id, "rule_version": str(rule.rule_version),
                     "fact_ref": spec.fact_ref},
                )
                await self._emit(
                    execution, ExecutionEventType.STEP_ADDED_TO_PLAN,
                    {"step_type": str(spec.step_type), "rule_id": rule.rule_id},
                )

    async def _mark_service_validated(
        self,
        execution: ValidationExecution,
        service_asset_by_port: dict[int, str],
        port: int,
        basis: str,
    ) -> None:
        service_asset_id = service_asset_by_port.get(port)
        if service_asset_id is None:
            return
        await self._emit(execution, ExecutionEventType.SERVICE_CONTEXT_UPDATED, {
            "port": str(port), "service_state": str(ServiceEvidenceState.SERVICE_VALIDATED),
            "validation_basis": basis,
        })

    async def _enrich_validated_service(
        self,
        organization_id: str,
        service_asset_by_port: dict[int, str],
        port: int,
        outcome: ProtocolValidationOutcome,
    ) -> None:
        """M13 — enriches the EXISTING canonical SERVICE asset's bounded
        metadata once a protocol is genuinely validated. Idempotent:
        `update_metadata_for_org()` overwrites the same keys with the
        same values on every repeat run, so this converges rather than
        duplicating or drifting. Never touches asset identity — the
        protocol name, validator id/version, and bounded metadata fields
        are exactly the kind of mutable, non-identity-bearing facts
        `domain/inventory/identity.py`'s own docstring says must never
        be part of a SERVICE asset's external_id."""
        service_asset_id = service_asset_by_port.get(port)
        if service_asset_id is None:
            return
        metadata = {
            "protocol": outcome.validated_protocol or outcome.candidate_protocol,
            "validator_id": outcome.validator_id,
            "validator_version": str(outcome.validator_version),
            **outcome.metadata,
        }
        await self._tenant_asset_service.update_metadata_for_org(
            organization_id, service_asset_id, metadata,
        )

    async def _ingest_protocol_condition_findings(
        self,
        execution: ValidationExecution,
        organization_id: str,
        service_asset_by_port: dict[int, str],
        port: int,
        protocol: str,
        outcome: ProtocolValidationOutcome,
    ) -> int:
        """M13 — the ONLY protocol-validator-derived condition this
        milestone defines: a sensitive database/cache protocol
        genuinely confirmed reachable with no TLS/SSL support
        advertised at the protocol level (MySQL's capability-flags
        CLIENT_SSL bit, PostgreSQL's SSLRequest 'N' response — both
        real, deterministic facts the validators themselves already
        captured, never inferred from a version string). Returns 1 if a
        condition was ingested, 0 otherwise — the caller folds this into
        the same `conditions_ingested` counter every other condition
        path uses to decide whether to trigger M9 correlation
        re-evaluation."""
        service_asset_id = service_asset_by_port.get(port)
        if service_asset_id is None:
            return 0
        no_tls_evidence = (
            outcome.metadata.get("supports_ssl") == "False"
            or outcome.metadata.get("ssl_supported") == "False"
        )
        if not no_tls_evidence:
            return 0

        from redforge.application.security_conditions.ingestion import SecurityConditionInput

        await self._security_condition_service.ingest(SecurityConditionInput(
            organization_id=organization_id,
            affected_asset_id=service_asset_id,
            source_category=_NETWORK_DISCOVERY_SOURCE_CATEGORY,
            stable_rule_id=_PLAINTEXT_SENSITIVE_SERVICE_RULE_ID,
            evidence_state="validated",
            severity="medium",
            title="Sensitive service reachable without TLS support",
            summary=(
                f"{protocol.upper()} on tcp/{port} advertised no TLS/SSL support at "
                f"the protocol level."
            ),
            qualifier=str(port),
        ))
        await self._emit(
            execution, ExecutionEventType.CONDITION_INGESTED,
            {"stable_rule_id": _PLAINTEXT_SENSITIVE_SERVICE_RULE_ID, "port": str(port)},
        )
        return 1

    async def _ingest_sensitive_service_condition(
        self, organization_id: str, service_asset_id: str, port: int,
    ) -> None:
        """Reuses M6's EXACT condition shape (`source_category=
        "network_discovery"`, `stable_rule_id="SENSITIVE_SERVICE_OBSERVED"`)
        so M9's existing `PUBLIC_SENSITIVE_SERVICE_CONTEXT` correlation
        rule recognizes this fact with zero changes to M9 itself — see
        application/network_discovery/analysis_service.py and
        application/security_correlation/rules.py."""
        from redforge.application.security_conditions.ingestion import SecurityConditionInput

        service_name = sensitive_service_name(port)
        await self._security_condition_service.ingest(SecurityConditionInput(
            organization_id=organization_id,
            affected_asset_id=service_asset_id,
            source_category=_NETWORK_DISCOVERY_SOURCE_CATEGORY,
            stable_rule_id=_SENSITIVE_SERVICE_RULE_ID,
            evidence_state="observed",
            severity="medium",
            title="Sensitive service observed",
            summary=f"{service_name.upper()} observed on tcp/{port}.",
        ))

    async def _evaluate_correlations_best_effort(
        self, execution: ValidationExecution, organization_id: str,
    ) -> None:
        """Bounded post-processing step, best-effort: a correlation
        evaluation failure is logged and surfaced via a real event —
        never silently swallowed, and never allowed to corrupt or block
        the execution's own truth (matching M6's `_ingest_conditions_
        best_effort` precedent, applied here to M9's existing, reused
        `TenantSecurityCorrelationService.evaluate()`)."""
        if self._correlation_service is None:
            return
        try:
            summary = await self._correlation_service.evaluate(organization_id)
        except Exception as exc:  # deliberately broad, see docstring
            await self._emit(
                execution, ExecutionEventType.CORRELATION_EVALUATED,
                {"error": "evaluation_failed", "detail": type(exc).__name__},
            )
            return
        await self._emit(execution, ExecutionEventType.CORRELATION_EVALUATED, {
            "rules_evaluated": str(summary.rules_evaluated),
            "created": str(summary.created), "updated": str(summary.updated),
            "resolved": str(summary.resolved),
        })
