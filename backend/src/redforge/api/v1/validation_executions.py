"""Gated Safe Active Validation REST API — M11.

Every route is tenant-scoped via TenantContext. organization_id is
NEVER accepted from the client. The client selects a canonical target
and a closed profile — never a step, port, command, or module; the
server builds the entire execution plan (see
application/validation_execution/step_planner.py).

Route ordering matters: literal-path routes (/summary) are registered
BEFORE the /{execution_id} parametrized routes so they are not
swallowed by the path parameter.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_validation_execution_service
from redforge.api.security import TenantContext, require_permission
from redforge.application.validation_execution.discovery_port_policy import is_sensitive_port

# FastAPI/Pydantic resolve annotations at runtime despite `from __future__
# import annotations` — this import must stay a real import, not
# TYPE_CHECKING-only (matches api/v1/authorizations.py's precedent).
from redforge.application.validation_execution.execution_service import (
    ValidationExecutionService,  # noqa: TC001
)
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.validation_execution.execution_service import (
        EventDTO,
        StepDTO,
        ValidationExecutionDTO,
    )

router = APIRouter(prefix="/validation-executions", tags=["validation-executions"])

# M13 — the closed set of protocol-candidate step types and the
# candidate protocol name each represents, mirroring
# execution_service._STEP_TYPE_TO_PROTOCOL exactly (kept as a small,
# local, read-only copy here rather than importing execution_service's
# module-private constant — this file already avoids importing
# execution internals beyond the public service/DTO surface).
_PROTOCOL_STEP_HINT: dict[str, str] = {
    "ssh_banner": "ssh",
    "mysql_handshake": "mysql",
    "postgresql_handshake": "postgresql",
    "redis_ping": "redis",
}


# ─── Request/Response Models ──────────────────────────────────────────────────


class CreateExecutionRequest(BaseModel):
    """organization_id and requester_user_id are intentionally NOT
    fields — derived from the caller's verified TenantContext. There is
    no field for steps, ports, commands, or modules — the server builds
    the entire plan from the canonical target's own endpoint."""

    target_id: str
    profile: str = Field(default="safe_active_baseline_v1")


class CancelRequest(BaseModel):
    pass


class StepResponse(BaseModel):
    id: str
    step_type: str
    order: int
    status: str
    started_at: str | None
    completed_at: str | None
    evidence: list[dict[str, str]]
    error_category: str | None
    source: str
    adaptive_rule_id: str | None
    adaptive_rule_version: int | None
    source_fact_ref: str | None
    # M13 — which ProtocolValidator (if any) produced this step's
    # outcome, and the resulting ProtocolValidationState. None for
    # every non-protocol step type.
    validator_id: str | None = None
    validator_version: int | None = None
    protocol_validation_state: str | None = None

    @classmethod
    def from_dto(cls, dto: StepDTO) -> StepResponse:
        return cls(
            id=dto.id, step_type=dto.step_type, order=dto.order, status=dto.status,
            started_at=dto.started_at, completed_at=dto.completed_at,
            evidence=dto.evidence, error_category=dto.error_category,
            source=dto.source, adaptive_rule_id=dto.adaptive_rule_id,
            adaptive_rule_version=dto.adaptive_rule_version,
            source_fact_ref=dto.source_fact_ref,
            validator_id=dto.validator_id, validator_version=dto.validator_version,
            protocol_validation_state=dto.protocol_validation_state,
        )


class PlanSummaryResponse(BaseModel):
    """Backend-derived plan-evolution counts — M12. Never client-side
    computed; derived entirely from the persisted step snapshot."""

    initial_step_count: int
    adaptive_step_count: int
    discovered_address_count: int
    reachable_port_count: int
    validated_service_count: int
    condition_count: int


def _build_plan_summary(dto: ValidationExecutionDTO) -> PlanSummaryResponse:
    initial = [s for s in dto.steps if s.source == "initial"]
    adaptive = [s for s in dto.steps if s.source == "adaptive"]

    discovered_addresses = 0
    reachable_ports = 0
    sensitive_reachable_ports = 0
    discovery_step = next((s for s in dto.steps if s.step_type == "port_discovery"), None)
    if discovery_step is not None:
        for e in discovery_step.evidence:
            if e["value"].startswith("reachable:"):
                reachable_ports += 1
                port_label = e["label"].removeprefix("port_")
                if port_label.isdigit() and is_sensitive_port(int(port_label)):
                    sensitive_reachable_ports += 1
    dns_step = next((s for s in dto.steps if s.step_type == "dns_resolution"), None)
    if dns_step is not None:
        for e in dns_step.evidence:
            if e["label"] == "resolved_addresses" and e["value"]:
                discovered_addresses = len(e["value"].split(","))

    validated_service_count = len({
        s.source_fact_ref for s in adaptive
        if s.source_fact_ref and (
            (s.status == "completed" and s.step_type in ("http_metadata", "tls_handshake"))
            or (s.step_type in _PROTOCOL_STEP_HINT and s.protocol_validation_state == "validated")
        )
    })
    # "rule" evidence entries appear on both http_security_headers
    # (M11 header findings) and tls_handshake (M13 TLS findings) steps.
    rule_condition_count = sum(
        1 for s in dto.steps if s.step_type in ("http_security_headers", "tls_handshake")
        for e in s.evidence if e["label"] == "rule"
    )
    # M13 — PLAINTEXT_SENSITIVE_SERVICE_OBSERVED is ingested whenever a
    # validated MySQL/PostgreSQL step's own evidence shows no TLS/SSL
    # support — the exact same signal execution_service's
    # _ingest_protocol_condition_findings() checks, read back here
    # rather than re-queried, to avoid a second DB round-trip.
    plaintext_sensitive_count = sum(
        1 for s in dto.steps
        if s.step_type in ("mysql_handshake", "postgresql_handshake")
        and s.protocol_validation_state == "validated"
        for e in s.evidence
        if e["label"] in ("supports_ssl", "ssl_supported") and e["value"] == "False"
    )
    condition_count = rule_condition_count + sensitive_reachable_ports + plaintext_sensitive_count

    return PlanSummaryResponse(
        initial_step_count=len(initial),
        adaptive_step_count=len(adaptive),
        discovered_address_count=discovered_addresses,
        reachable_port_count=reachable_ports,
        validated_service_count=validated_service_count,
        condition_count=condition_count,
    )


class ExecutionResponse(BaseModel):
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
    steps: list[StepResponse]
    plan_summary: PlanSummaryResponse

    @classmethod
    def from_dto(cls, dto: ValidationExecutionDTO) -> ExecutionResponse:
        return cls(
            id=dto.id, organization_id=dto.organization_id, target_id=dto.target_id,
            requester_user_id=dto.requester_user_id, profile=dto.profile, status=dto.status,
            policy_decision_id=dto.policy_decision_id, policy_reason_code=dto.policy_reason_code,
            cancellation_requested=dto.cancellation_requested,
            created_at=dto.created_at, updated_at=dto.updated_at,
            started_at=dto.started_at, completed_at=dto.completed_at,
            failure_reason=dto.failure_reason,
            steps=[StepResponse.from_dto(s) for s in dto.steps],
            plan_summary=_build_plan_summary(dto),
        )


class EventResponse(BaseModel):
    id: str
    execution_id: str
    sequence: int
    event_type: str
    payload: dict[str, str]
    occurred_at: str

    @classmethod
    def from_dto(cls, dto: EventDTO) -> EventResponse:
        return cls(
            id=dto.id, execution_id=dto.execution_id, sequence=dto.sequence,
            event_type=dto.event_type, payload=dto.payload, occurred_at=dto.occurred_at,
        )


class ResultResponse(BaseModel):
    """Crisp, structured result — no story prose. Derived entirely from
    already-persisted step evidence; no separate computation path that
    could drift from what actually happened."""

    execution_id: str
    target_id: str
    status: str
    tcp_reachable: bool | None
    application_layer_validated: bool | None
    validation_basis: str | None
    tls_protocol_version: str | None
    http_status_code: str | None
    conditions_observed: list[str]
    failed_steps: list[str]
    created_at: str
    started_at: str | None
    completed_at: str | None
    # M12 — populated only for NETWORK_DISCOVERY_BASELINE_V1 executions.
    discovered_addresses: list[str] = Field(default_factory=list)
    reachable_ports: list[int] = Field(default_factory=list)
    validated_services: list[dict[str, str]] = Field(default_factory=list)
    correlations_created: int | None = None
    correlations_updated: int | None = None
    correlations_resolved: int | None = None


def _build_result(dto: ValidationExecutionDTO) -> ResultResponse:
    by_type = {s.step_type: s for s in dto.steps}
    reachability = by_type.get("service_reachability")
    discovery_step = by_type.get("port_discovery")
    dns_step = by_type.get("dns_resolution")

    discovered_addresses: list[str] = []
    if dns_step is not None:
        for item in dns_step.evidence:
            if item.get("label") == "resolved_addresses" and item.get("value"):
                discovered_addresses = item["value"].split(",")

    discovered_reachable_ports: list[int] = []
    validated_services: list[dict[str, str]] = []
    if discovery_step is not None:
        for item in discovery_step.evidence:
            label, value = item.get("label", ""), item.get("value", "")
            if not label.startswith("port_") or ":" not in value:
                continue
            port_str = label.removeprefix("port_")
            outcome, _, hint = value.partition(":")
            if outcome == "reachable" and port_str.isdigit():
                discovered_reachable_ports.append(int(port_str))
                validated_services.append({
                    "port": port_str, "hint": hint, "state": "hinted",
                    "validator_id": "", "validator_version": "",
                })
    for adaptive_step in dto.steps:
        if (
            adaptive_step.source == "adaptive"
            and adaptive_step.status == "completed"
            and adaptive_step.step_type in ("http_metadata", "tls_handshake")
            and adaptive_step.source_fact_ref
        ):
            fact_ref = adaptive_step.source_fact_ref
            port = fact_ref.split(":")[1] if ":" in fact_ref else ""
            for svc in validated_services:
                if svc["port"] == port:
                    svc["state"] = "validated"
        # M13 — protocol-candidate steps carry their own STRUCTURED
        # validated/hinted/inconclusive truth (protocol_validation_state)
        # and validator provenance — read directly, never re-derived by
        # string-parsing evidence the way the M12 HTTP/TLS branch above
        # still does for backward compatibility.
        if (
            adaptive_step.source == "adaptive"
            and adaptive_step.step_type in _PROTOCOL_STEP_HINT
            and adaptive_step.source_fact_ref
        ):
            fact_ref = adaptive_step.source_fact_ref
            port = fact_ref.split(":")[1] if ":" in fact_ref else ""
            is_validated = adaptive_step.protocol_validation_state == "validated"
            state = "validated" if is_validated else "hinted"
            entry = {
                "port": port, "hint": _PROTOCOL_STEP_HINT[adaptive_step.step_type], "state": state,
                "validator_id": adaptive_step.validator_id or "",
                "validator_version": (
                    str(adaptive_step.validator_version)
                    if adaptive_step.validator_version is not None else ""
                ),
            }
            existing = next((svc for svc in validated_services if svc["port"] == port), None)
            if existing is not None:
                existing.update(entry)
            else:
                validated_services.append(entry)

    def _evidence_value(step: StepDTO | None, label: str) -> str | None:
        if step is None:
            return None
        for item in step.evidence:
            if item.get("label") == label:
                return item.get("value")
        return None

    tls_step = by_type.get("tls_handshake")
    http_step = by_type.get("http_metadata")
    headers_step = by_type.get("http_security_headers")

    conditions = [
        item["value"] for item in (headers_step.evidence if headers_step else [])
        if item.get("label") == "rule"
    ]
    failed_steps = [s.step_type for s in dto.steps if s.status in ("failed", "timed_out")]

    return ResultResponse(
        execution_id=dto.id,
        target_id=dto.target_id,
        status=dto.status,
        tcp_reachable=(
            _evidence_value(reachability, "tcp_reachable") == "True" if reachability else None
        ),
        application_layer_validated=(
            _evidence_value(reachability, "application_layer_validated") == "True"
            if reachability else None
        ),
        validation_basis=_evidence_value(reachability, "validation_basis"),
        tls_protocol_version=_evidence_value(tls_step, "protocol_version"),
        http_status_code=_evidence_value(http_step, "status_code"),
        conditions_observed=conditions,
        failed_steps=failed_steps,
        created_at=dto.created_at,
        started_at=dto.started_at,
        completed_at=dto.completed_at,
        discovered_addresses=discovered_addresses,
        reachable_ports=discovered_reachable_ports,
        validated_services=validated_services,
    )


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", response_model=ExecutionResponse, status_code=201)
async def create_execution(
    body: CreateExecutionRequest,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_RUN)),
    service: ValidationExecutionService = Depends(get_validation_execution_service),
) -> ExecutionResponse:
    """Create and run a Gated Safe Active Validation execution against
    an authorized canonical target. Performs a fresh M10 policy
    decision before any network activity; a DENY or APPROVAL_REQUIRED
    decision returns a DENIED execution with zero steps ever created."""
    dto = await service.create_and_run(
        organization_id=tenant.organization_id,
        target_id=body.target_id,
        requester_user_id=tenant.user_id,
        profile=body.profile,
    )
    return ExecutionResponse.from_dto(dto)


@router.get("", response_model=list[ExecutionResponse])
async def list_executions(
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_READ)),
    service: ValidationExecutionService = Depends(get_validation_execution_service),
) -> list[ExecutionResponse]:
    dtos = await service.list_by_organization(tenant.organization_id, status, limit, offset)
    return [ExecutionResponse.from_dto(d) for d in dtos]


@router.get("/summary", response_model=dict[str, int])
async def get_execution_summary(
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_READ)),
    service: ValidationExecutionService = Depends(get_validation_execution_service),
) -> dict[str, int]:
    """Backend-derived lifecycle counts — never a client-side fabricated trend."""
    return await service.summary(tenant.organization_id)


@router.get("/{execution_id}", response_model=ExecutionResponse)
async def get_execution(
    execution_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_READ)),
    service: ValidationExecutionService = Depends(get_validation_execution_service),
) -> ExecutionResponse:
    dto = await service.get_by_id(tenant.organization_id, execution_id)
    return ExecutionResponse.from_dto(dto)


@router.get("/{execution_id}/steps", response_model=list[StepResponse])
async def list_steps(
    execution_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_READ)),
    service: ValidationExecutionService = Depends(get_validation_execution_service),
) -> list[StepResponse]:
    dto = await service.get_by_id(tenant.organization_id, execution_id)
    return [StepResponse.from_dto(s) for s in dto.steps]


@router.get("/{execution_id}/events", response_model=list[EventResponse])
async def list_events(
    execution_id: str,
    after_sequence: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=500),
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_READ)),
    service: ValidationExecutionService = Depends(get_validation_execution_service),
) -> list[EventResponse]:
    """Live progress. Polling-based (see execution_service.py's module
    docstring for why: no SSE precedent existed in this codebase, and
    polling is real, backend-derived progress — never faked — and
    simpler to prove deterministically in an automated test suite)."""
    events = await service.list_events(tenant.organization_id, execution_id, after_sequence, limit)
    return [EventResponse.from_dto(e) for e in events]


@router.get("/{execution_id}/result", response_model=ResultResponse)
async def get_result(
    execution_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_READ)),
    service: ValidationExecutionService = Depends(get_validation_execution_service),
) -> ResultResponse:
    dto = await service.get_by_id(tenant.organization_id, execution_id)
    result = _build_result(dto)

    events = await service.list_events(tenant.organization_id, execution_id, 0, 500)
    correlation_event = next(
        (e for e in reversed(events) if e.event_type == "correlation_evaluated"), None,
    )
    if correlation_event is not None and "error" not in correlation_event.payload:
        result = result.model_copy(update={
            "correlations_created": int(correlation_event.payload.get("created", 0)),
            "correlations_updated": int(correlation_event.payload.get("updated", 0)),
            "correlations_resolved": int(correlation_event.payload.get("resolved", 0)),
        })
    return result


@router.post("/{execution_id}/cancel", response_model=ExecutionResponse)
async def cancel_execution(
    execution_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_RUN)),
    service: ValidationExecutionService = Depends(get_validation_execution_service),
) -> ExecutionResponse:
    dto = await service.cancel(tenant.organization_id, execution_id, tenant.user_id)
    return ExecutionResponse.from_dto(dto)
