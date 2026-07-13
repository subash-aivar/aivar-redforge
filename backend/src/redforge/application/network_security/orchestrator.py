"""NetworkValidationOrchestrator — M16.

The canonical orchestrator for one authorized NetworkValidationRun:
    RESOLVE_TARGET -> VALIDATE_SCOPE -> HOST_REACHABILITY ->
    TCP_SERVICE_DISCOVERY -> PROTOCOL_VALIDATION -> TLS_VALIDATION ->
    (M6 asset/relationship resolution + condition ingestion) ->
    CORRELATION_EVALUATION -> SNAPSHOT -> DRIFT

Reuses, unchanged:
  - M6's TenantNetworkDiscoveryService for canonical AIAsset (IP_ADDRESS/
    HOST/SERVICE) + relationship resolution, and its own
    list_exposure_observations() for the 3 M6 network conditions.
  - M11/M13's pure network primitives (check_tcp_connectivity,
    perform_tls_handshake, evaluate_tls_findings,
    ProtocolValidatorRegistry) — address/port/timeout signature, no
    AITarget dependency.
  - M9's TenantSecurityCorrelationService.evaluate() — the existing
    rule registry already fires against the AIAsset/SecurityCondition
    facts this orchestrator produces; no new rule needed.

Every concrete address is authorization-checked TWICE: once when the
plan is built (VALIDATE_SCOPE) and again immediately before its own
probe (defense in depth against a scope change mid-run — see
NetworkAuthorizationScopeChecker's own docstring on why nothing is
cached).

Persisted NetworkObservation `data` fields are an explicit allowlist —
never a raw banner, credential, Authorization header, cookie, private
key, or full response body:
  - tcp_reachability: {"port": "443", "reachable": "true"}
  - protocol_validation: {"validator_id": ..., "validated_protocol": ...}
    plus each validator's own already-bounded/sanitized metadata dict
    (see ProtocolValidationOutcome's own docstring).
  - tls_validation: {"fingerprint_sha256": ..., "issuer_common_name":
    ..., "subject_common_name": ..., "not_before": ..., "not_after":
    ..., "protocol_version": ...}
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from redforge.application.network_discovery.observations import (
    HostObservation,
    IPAddressObservation,
    NetworkDiscoveryResult,
    ServiceObservation,
)
from redforge.application.network_discovery.scan_adapter import _WELL_KNOWN_PORTS
from redforge.application.network_discovery.service import TenantNetworkDiscoveryService
from redforge.application.network_security.authorization_scope import (
    NetworkAuthorizationScopeChecker,
)
from redforge.application.network_security.planner import build_plan
from redforge.application.validation_execution.network_adapters import (
    check_tcp_connectivity,
    evaluate_tls_findings,
    perform_tls_handshake,
)
from redforge.application.validation_execution.protocol_validators import (
    default_protocol_validator_registry,
)
from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import AssetType
from redforge.domain.network_security.address import (
    NetworkAddressError,
    expand_cidr_bounded,
    normalize_and_classify,
)
from redforge.domain.network_security.entity import (
    NetworkDriftEvent,
    NetworkServiceSnapshotEntry,
    NetworkStateSnapshot,
    NetworkValidationRun,
)
from redforge.domain.network_security.value_objects import (
    NETWORK_DRIFT_CATEGORIES,
    NetworkRunStatus,
    NetworkScopeReasonCode,
    NetworkValidationProfile,
    SecurityDriftCategory,
)
from redforge.infrastructure.database.repositories.network_security.drift_repository import (
    SqlAlchemyNetworkDriftEventRepository,
)
from redforge.infrastructure.database.repositories.network_security.event_repository import (
    SqlAlchemyNetworkRunEventRepository,
)
from redforge.infrastructure.database.repositories.network_security.observation_repository import (
    SqlAlchemyNetworkObservationRepository,
)
from redforge.infrastructure.database.repositories.network_security.run_repository import (
    SqlAlchemyNetworkValidationRunRepository,
)
from redforge.infrastructure.database.repositories.network_security.snapshot_repository import (
    SqlAlchemyNetworkStateSnapshotRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.inventory.tenant_asset_service import TenantAssetService
    from redforge.application.security_conditions.service import TenantSecurityConditionService
    from redforge.application.security_correlation.service import (
        TenantSecurityCorrelationService,
    )

CONNECT_TIMEOUT_SECONDS = 1.0
MAX_CONCURRENCY = 16
CONNECTOR_ID = "network_security_m16"
# Server-controlled wall-clock deadline for one run's ENTIRE probe
# phase (not per-probe — see CONNECT_TIMEOUT_SECONDS for that). Once
# exceeded, no NEW probe starts (already-in-flight probes still
# complete/timeout normally) — a bounded backstop against pathological
# slow-network conditions across a large plan, independent of the
# per-probe timeout and the concurrency semaphore.
EXECUTION_DEADLINE_SECONDS = 60.0

_TLS_CANDIDATE_PORTS: frozenset[int] = frozenset({443, 8443})


@dataclass(frozen=True, slots=True)
class NetworkValidationRunDTO:
    id: str
    organization_id: str
    target_asset_id: str
    profile: str
    status: str
    authorization_id: str | None
    failure_reason: str
    reachable_ports: list[int]
    denied_addresses: list[str]


@dataclass
class _ServiceFinding:
    address: str
    port: int
    validated_protocol: str | None = None
    validator_id: str | None = None
    tls_fingerprint_sha256: str | None = None


class NetworkValidationOrchestrator:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        asset_service: TenantAssetService,
        condition_service: TenantSecurityConditionService,
        correlation_service: TenantSecurityCorrelationService,
    ) -> None:
        self._session_factory = session_factory
        self._asset_service = asset_service
        self._condition_service = condition_service
        self._correlation_service = correlation_service
        self._discovery_service = TenantNetworkDiscoveryService(asset_service, condition_service)
        self._protocol_registry = default_protocol_validator_registry()

    async def create_and_run(
        self,
        organization_id: str,
        target_asset_id: str,
        requester_user_id: str,
        profile: NetworkValidationProfile,
        trigger: str = "manual",
        continuous_policy_id: str | None = None,
        scheduled_due_at: datetime | None = None,
    ) -> NetworkValidationRunDTO:
        run = NetworkValidationRun.create(
            organization_id=EntityId.from_string(organization_id),
            target_asset_id=EntityId.from_string(target_asset_id),
            requester_user_id=EntityId.from_string(requester_user_id),
            profile=profile,
            trigger=trigger,
            continuous_policy_id=(
                EntityId.from_string(continuous_policy_id) if continuous_policy_id else None
            ),
            scheduled_due_at=scheduled_due_at,
        )
        await self._save_run(run)
        await self._append_run_event(run, "run_created", {})

        run.begin_policy_check()
        await self._save_run(run)

        target_asset = await self._asset_service.get_for_org(target_asset_id, organization_id)
        try:
            candidate_addresses = self._candidate_addresses(target_asset)
        except NetworkAddressError as exc:
            run.deny(NetworkScopeReasonCode.NO_MATCHING_AUTHORIZATION.value)
            await self._save_run(run)
            await self._append_run_event(run, "policy_denied", {"reason": str(exc)})
            return self._to_dto(run, [], [])

        authorized_addresses, denied_addresses, authorization_id = (
            await self._authorize_addresses(organization_id, candidate_addresses)
        )
        if not authorized_addresses:
            run.deny(NetworkScopeReasonCode.NO_MATCHING_AUTHORIZATION.value)
            await self._save_run(run)
            await self._append_run_event(
                run, "policy_denied",
                {"reason_code": NetworkScopeReasonCode.NO_MATCHING_AUTHORIZATION.value},
            )
            return self._to_dto(run, [], denied_addresses)

        assert authorization_id is not None  # authorized_addresses non-empty implies a match
        run.authorize(EntityId.from_string(authorization_id))
        await self._save_run(run)
        await self._append_run_event(run, "run_authorized", {"authorization_id": authorization_id})

        run.start()
        await self._save_run(run)
        await self._append_run_event(run, "run_started", {})

        try:
            reachable_ports, findings = await self._execute_validation(
                organization_id, run, profile, authorized_addresses,
            )
        except Exception:
            logger.warning(
                "network_security: run %s failed during execution", str(run.id), exc_info=True,
            )
            run.finish(NetworkRunStatus.FAILED, {"reason": "execution_error"})
            await self._save_run(run)
            await self._append_run_event(run, "run_finished", {"status": "failed"})
            return self._to_dto(run, [], denied_addresses)

        if await self._is_cancellation_requested(organization_id, str(run.id)):
            # Terminal transition only — never _reconcile(). Any partial
            # observations already persisted (append-only, best-effort)
            # remain, but no NEW SecurityCondition ingestion, no drift
            # computation, and no snapshot is built from this run's
            # incomplete results: doing so could falsely resolve a
            # condition whose probe never ran, or falsely report a
            # disappearance drift for a port/service that was simply
            # never reached rather than genuinely gone.
            run.cancel()
            await self._save_run(run)
            await self._append_run_event(run, "run_finished", {"status": "cancelled"})
            return self._to_dto(run, reachable_ports, denied_addresses)

        status = (
            NetworkRunStatus.COMPLETED if not denied_addresses
            else NetworkRunStatus.PARTIALLY_COMPLETED
        )
        run.finish(status)
        await self._save_run(run)
        await self._append_run_event(run, "run_finished", {"status": str(status)})

        await self._reconcile(organization_id, run, target_asset.id, reachable_ports, findings)

        return self._to_dto(run, reachable_ports, denied_addresses)

    # ─── Address resolution / authorization ────────────────────────────────

    def _candidate_addresses(self, target_asset: Any) -> list[str]:
        if target_asset.asset_type == AssetType.IP_ADDRESS.value:
            raw_ip = target_asset.external_id.partition(":")[2]
            normalized = normalize_and_classify(raw_ip)
            return [normalized.value]
        if target_asset.asset_type == AssetType.NETWORK.value:
            cidr = target_asset.external_id.partition(":")[2]
            return expand_cidr_bounded(cidr)
        raise NetworkAddressError(
            f"Asset type '{target_asset.asset_type}' is not a valid network validation target "
            "(must be IP_ADDRESS or NETWORK)"
        )

    async def _authorize_addresses(
        self, organization_id: str, candidates: list[str],
    ) -> tuple[list[str], list[str], str | None]:
        from redforge.infrastructure.database.repositories.asset_repository import (
            SqlAlchemyAssetRepository,
        )
        from redforge.infrastructure.database.repositories.authorization.repository import (
            SqlAlchemySecurityAuthorizationRepository,
        )

        authorized: list[str] = []
        denied: list[str] = []
        matched_authorization_id: str | None = None

        async with self._session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            for address in candidates:
                decision = await checker.check_ip_authorized(organization_id, address)
                if decision.allowed:
                    authorized.append(address)
                    if matched_authorization_id is None:
                        matched_authorization_id = decision.authorization_id
                else:
                    denied.append(address)

        return authorized, denied, matched_authorization_id

    async def _reverify_address(self, organization_id: str, address: str) -> bool:
        """Fresh, uncached re-check immediately before this address's
        own probe — see module docstring."""
        from redforge.infrastructure.database.repositories.asset_repository import (
            SqlAlchemyAssetRepository,
        )
        from redforge.infrastructure.database.repositories.authorization.repository import (
            SqlAlchemySecurityAuthorizationRepository,
        )

        async with self._session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            decision = await checker.check_ip_authorized(organization_id, address)
        return decision.allowed

    # ─── Execution ──────────────────────────────────────────────────────────

    async def _execute_validation(
        self,
        organization_id: str,
        run: NetworkValidationRun,
        profile: NetworkValidationProfile,
        authorized_addresses: list[str],
    ) -> tuple[list[int], list[_ServiceFinding]]:
        if await self._is_cancellation_requested(organization_id, str(run.id)):
            return [], []

        previously_known_ports = await self._previously_known_ports(organization_id, run)
        plan = build_plan(profile, tuple(authorized_addresses), previously_known_ports)

        semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
        findings: list[_ServiceFinding] = []
        reachable_ports: set[int] = set()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + EXECUTION_DEADLINE_SECONDS

        async def _probe(address: str, port: int) -> None:
            # Deadline check FIRST, before acquiring the semaphore or
            # doing any I/O — once exceeded, no new probe starts. This
            # is a scheduling backstop (bounded total wall-clock spend
            # per run), distinct from CONNECT_TIMEOUT_SECONDS (bounded
            # per-probe) and MAX_CONCURRENCY (bounded in-flight count).
            if loop.time() >= deadline:
                return
            # Cancellation checkpoint #1: before acquiring the semaphore
            # or doing any I/O — mirrors the deadline check above.
            if await self._is_cancellation_requested(organization_id, str(run.id)):
                return
            # The semaphore wraps the ENTIRE probe body — including the
            # authorization re-check — not just the TCP connect. A
            # semaphore around only the connect call still lets every
            # (address, port) pair's reverify_address() open its own DB
            # session concurrently and unboundedly (up to
            # len(addresses) * len(ports) at once for a large
            # NETWORK_DEEP_SAFE plan); bounding the whole body here
            # caps total in-flight DB sessions/connects to
            # MAX_CONCURRENCY, closing that resource-exhaustion risk.
            async with semaphore:
                if not await self._reverify_address(organization_id, address):
                    return
                # Cancellation checkpoint #2: after M10 authorization is
                # freshly reverified but before the TCP connect itself —
                # never skips or bypasses the authorization recheck.
                if await self._is_cancellation_requested(organization_id, str(run.id)):
                    return
                tcp_result = await check_tcp_connectivity(address, port, CONNECT_TIMEOUT_SECONDS)
            await self._append_observation(
                organization_id, run, address, "tcp_reachability", "tcp_connect",
                "reachable" if tcp_result.reachable else "not_observed",
                {"port": str(port), "reachable": str(tcp_result.reachable)},
            )
            if not tcp_result.reachable:
                return
            reachable_ports.add(port)
            finding = _ServiceFinding(address=address, port=port)

            if port in _TLS_CANDIDATE_PORTS:
                tls = await perform_tls_handshake(address, address, port, CONNECT_TIMEOUT_SECONDS)
                if tls.success:
                    finding.validated_protocol = "tls"
                    finding.tls_fingerprint_sha256 = tls.fingerprint_sha256
                    await self._append_observation(
                        organization_id, run, address, "tls_validation", "tls_handshake",
                        "validated",
                        {
                            "fingerprint_sha256": tls.fingerprint_sha256 or "",
                            "issuer_common_name": tls.issuer_common_name or "",
                            "subject_common_name": tls.subject_common_name or "",
                            "not_before": tls.not_before or "",
                            "not_after": tls.not_after or "",
                            "protocol_version": tls.protocol_version or "",
                        },
                    )
                    now_utc = datetime.now(UTC).isoformat()
                    for tls_finding in evaluate_tls_findings(tls, now_utc):
                        await self._ingest_condition_best_effort(
                            organization_id, address, port, tls_finding.stable_rule_id,
                            tls_finding.title, tls_finding.summary,
                        )
            else:
                candidate_protocol = _WELL_KNOWN_PORTS.get(port, "")
                validator = self._protocol_registry.get_for_protocol(candidate_protocol)
                if validator is not None:
                    outcome = await validator.validate(address, port, CONNECT_TIMEOUT_SECONDS)
                    if outcome.validated_protocol:
                        finding.validated_protocol = outcome.validated_protocol
                        finding.validator_id = outcome.validator_id
                    await self._append_observation(
                        organization_id, run, address, "protocol_validation",
                        outcome.validator_id, str(outcome.state),
                        {
                            "validator_id": outcome.validator_id,
                            "validated_protocol": outcome.validated_protocol or "",
                            **outcome.metadata,
                        },
                    )
            findings.append(finding)

        await asyncio.gather(
            *(_probe(addr, port) for addr in plan.addresses for port in plan.ports)
        )
        return sorted(reachable_ports), findings

    async def _previously_known_ports(
        self, organization_id: str, run: NetworkValidationRun,
    ) -> tuple[int, ...]:
        if run.continuous_policy_id is None:
            return ()
        async with self._session_factory() as session:
            snapshot_repo = SqlAlchemyNetworkStateSnapshotRepository(session)
            previous = await snapshot_repo.get_latest_for_policy(
                run.continuous_policy_id, EntityId.from_string(organization_id),
            )
        return previous.reachable_ports if previous is not None else ()

    # ─── Asset / condition / correlation / snapshot / drift reconciliation ─

    async def _reconcile(
        self,
        organization_id: str,
        run: NetworkValidationRun,
        target_asset_id: str,
        reachable_ports: list[int],
        findings: list[_ServiceFinding],
    ) -> None:
        discovery_result = self._build_discovery_result(target_asset_id, reachable_ports, findings)
        if discovery_result.ip_addresses:
            await self._discovery_service.run_discovery(
                organization_id, CONNECTOR_ID, discovery_result,
            )
        await self._discovery_service.list_exposure_observations(organization_id)

        for f in findings:
            if f.validated_protocol and f.validated_protocol != "tls":
                await self._update_service_metadata(
                    organization_id, f, {"validated_protocol": f.validated_protocol},
                )
            if f.tls_fingerprint_sha256:
                await self._update_service_metadata(
                    organization_id, f, {"tls_fingerprint_sha256": f.tls_fingerprint_sha256},
                )

        await self._correlation_service.evaluate(organization_id)

        if run.continuous_policy_id is None:
            return

        related_asset_ids = await self._related_asset_ids(organization_id, target_asset_id)
        active_condition_keys = await self._active_condition_keys(
            organization_id, related_asset_ids,
        )
        active_correlation_keys = await self._active_correlation_keys(
            organization_id, related_asset_ids,
        )
        resolved_ips = [f.address for f in findings] or await self._resolved_ips_for_run(
            organization_id, str(run.id),
        )
        service_entries = tuple(
            NetworkServiceSnapshotEntry(
                port=f.port, validated_protocol=f.validated_protocol, validator_id=f.validator_id,
                tls_fingerprint_sha256=f.tls_fingerprint_sha256,
            )
            for f in findings
        )
        snapshot = NetworkStateSnapshot.build(
            organization_id=EntityId.from_string(organization_id),
            policy_id=run.continuous_policy_id,
            run_id=run.id,
            resolved_ips=list(dict.fromkeys(resolved_ips)),
            reachable_ports=reachable_ports,
            services=list(service_entries),
            active_condition_keys=active_condition_keys,
            active_correlation_keys=active_correlation_keys,
        )

        async with self._session_factory() as session:
            snapshot_repo = SqlAlchemyNetworkStateSnapshotRepository(session)
            previous = await snapshot_repo.get_latest_for_policy(
                run.continuous_policy_id, EntityId.from_string(organization_id),
            )
            await snapshot_repo.save(snapshot)
            await session.commit()

        first_observed_by_key = await self._active_condition_first_observed_at(
            organization_id, related_asset_ids,
        )
        reactivated_keys = _compute_reactivated_keys(previous, snapshot, first_observed_by_key)
        drift_events = _detect_drift(previous, snapshot, reactivated_keys)
        if drift_events:
            async with self._session_factory() as session:
                drift_repo = SqlAlchemyNetworkDriftEventRepository(session)
                for event in drift_events:
                    await drift_repo.append(event)
                await session.commit()

    def _build_discovery_result(
        self, target_asset_id: str, reachable_ports: list[int], findings: list[_ServiceFinding],
    ) -> NetworkDiscoveryResult:
        addresses = sorted({f.address for f in findings if f.port in reachable_ports})
        ip_observations = tuple(IPAddressObservation(ip=a) for a in addresses)
        host_observations: tuple[HostObservation, ...] = ()
        service_observations = tuple(
            ServiceObservation(
                host_ip=f.address, protocol="tcp", port=f.port, observed_state="open",
                safe_service_name=f.validated_protocol or _WELL_KNOWN_PORTS.get(f.port, ""),
            )
            for f in findings if f.port in reachable_ports
        )
        network_cidr = addresses[0] + "/32" if len(addresses) == 1 else "0.0.0.0/0"
        return NetworkDiscoveryResult(
            network_cidr=network_cidr, ip_addresses=ip_observations,
            hosts=host_observations, services=service_observations, errors=(),
        )

    async def _update_service_metadata(
        self, organization_id: str, finding: _ServiceFinding, metadata: dict[str, str],
    ) -> None:
        from redforge.domain.inventory.identity import build_external_id

        ip_external_id = build_external_id(IdentityScheme.IP_ADDRESS, finding.address)
        async with SessionUnitOfWork(self._session_factory) as uow:
            from redforge.infrastructure.database.repositories.asset_repository import (
                SqlAlchemyAssetRepository,
            )

            repo = SqlAlchemyAssetRepository(uow.session)
            ip_asset = await repo.get_by_external_id(organization_id, ip_external_id)
        if ip_asset is None:
            return
        relationships = await self._asset_service.get_relationships_for_org(
            str(ip_asset.id), organization_id,
        )
        for rel in relationships:
            if rel["relationship_type"] != "ip_assigned_to_host":
                continue
            host_relationships = await self._asset_service.get_relationships_for_org(
                rel["target_asset_id"], organization_id,
            )
            for host_rel in host_relationships:
                if host_rel["relationship_type"] != "host_exposes_service":
                    continue
                service_asset = await self._asset_service.get_for_org(
                    host_rel["target_asset_id"], organization_id,
                )
                if f":tcp:{finding.port}" in service_asset.external_id:
                    await self._asset_service.update_metadata_for_org(
                        organization_id, service_asset.id, metadata,
                    )

    async def _related_asset_ids(self, organization_id: str, target_asset_id: str) -> set[str]:
        relationships = await self._asset_service.get_relationships_for_org(
            target_asset_id, organization_id,
        )
        related = {target_asset_id} | {r["target_asset_id"] for r in relationships}
        for r in relationships:
            second_hop = await self._asset_service.get_relationships_for_org(
                r["target_asset_id"], organization_id,
            )
            related |= {rr["target_asset_id"] for rr in second_hop}
        return related

    async def _active_condition_keys(
        self, organization_id: str, related_asset_ids: set[str],
    ) -> list[str]:
        keys: list[str] = []
        for asset_id in related_asset_ids:
            conditions = await self._condition_service.list_active_for_asset(
                organization_id, asset_id,
            )
            keys.extend(c.identity_key for c in conditions if c.identity_key)
        return keys

    async def _active_condition_first_observed_at(
        self, organization_id: str, related_asset_ids: set[str],
    ) -> dict[str, str]:
        """Maps each active condition's identity_key to its own
        first_observed_at — the evidence `_compute_reactivated_keys`
        needs to distinguish a genuinely NEW condition (APPEARED) from
        one that already existed before the previous snapshot and is
        merely active again now (REACTIVATED)."""
        first_observed_by_key: dict[str, str] = {}
        for asset_id in related_asset_ids:
            conditions = await self._condition_service.list_active_for_asset(
                organization_id, asset_id,
            )
            for c in conditions:
                if c.identity_key:
                    first_observed_by_key[c.identity_key] = c.first_observed_at
        return first_observed_by_key

    async def _active_correlation_keys(
        self, organization_id: str, related_asset_ids: set[str],
    ) -> list[str]:
        if not related_asset_ids:
            return []
        correlations = await self._correlation_service.list_for_org(
            organization_id, lifecycle="active", limit=500,
        )
        return [
            c.identity_key for c in correlations
            if c.identity_key and set(c.entity_ids) & related_asset_ids
        ]

    async def _resolved_ips_for_run(self, organization_id: str, run_id: str) -> list[str]:
        async with self._session_factory() as session:
            obs_repo = SqlAlchemyNetworkObservationRepository(session)
            rows = await obs_repo.list_for_run(organization_id, run_id)
        return sorted({r.asset_id for r in rows})

    async def _ingest_condition_best_effort(
        self, organization_id: str, address: str, port: int, stable_rule_id: str,
        title: str, summary: str,
    ) -> None:
        from redforge.application.security_conditions.ingestion import SecurityConditionInput
        from redforge.domain.inventory.identity import build_external_id

        try:
            ip_external_id = build_external_id(IdentityScheme.IP_ADDRESS, address)
            async with SessionUnitOfWork(self._session_factory) as uow:
                from redforge.infrastructure.database.repositories.asset_repository import (
                    SqlAlchemyAssetRepository,
                )

                repo = SqlAlchemyAssetRepository(uow.session)
                ip_asset = await repo.get_by_external_id(organization_id, ip_external_id)
            if ip_asset is None:
                return
            await self._condition_service.ingest(
                SecurityConditionInput(
                    organization_id=organization_id,
                    affected_asset_id=str(ip_asset.id),
                    source_category="protocol_validation",
                    stable_rule_id=stable_rule_id,
                    qualifier=str(port),
                    evidence_state="observed",
                    severity="medium",
                    title=title,
                    summary=summary,
                )
            )
        except Exception:
            logger.warning(
                "network_security: TLS condition ingestion failed for rule_id=%s", stable_rule_id,
                exc_info=True,
            )

    # ─── Persistence helpers ────────────────────────────────────────────────

    async def _save_run(self, run: NetworkValidationRun) -> None:
        async with self._session_factory() as session:
            repo = SqlAlchemyNetworkValidationRunRepository(session)
            await repo.save(run)
            await session.commit()

    async def _is_cancellation_requested(self, organization_id: str, run_id: str) -> bool:
        """Fresh, uncached read against Postgres — never cached on the
        in-memory run/asyncio.Event, so a cancellation persisted by a
        concurrent HTTP request/session is observed on the very next
        checkpoint regardless of which process or task requested it."""
        async with self._session_factory() as session:
            repo = SqlAlchemyNetworkValidationRunRepository(session)
            return await repo.is_cancellation_requested(
                EntityId.from_string(run_id), EntityId.from_string(organization_id),
            )

    async def request_cancellation(self, organization_id: str, run_id: str) -> str | None:
        """Idempotent: returns the run's current status if it exists for
        this tenant (whether or not it was already terminal/already
        requested), or None if no such run exists for this tenant."""
        async with self._session_factory() as session:
            repo = SqlAlchemyNetworkValidationRunRepository(session)
            status = await repo.request_cancellation(
                EntityId.from_string(run_id), EntityId.from_string(organization_id),
            )
            await session.commit()
            return status

    async def _append_run_event(
        self, run: NetworkValidationRun, event_type: str, payload: dict[str, str],
    ) -> None:
        async with self._session_factory() as session:
            repo = SqlAlchemyNetworkRunEventRepository(session)
            await repo.append(
                organization_id=str(run.organization_id), run_id=str(run.id),
                event_type=event_type, payload=payload, occurred_at=datetime.now(UTC),
            )
            await session.commit()

    async def _append_observation(
        self, organization_id: str, run: NetworkValidationRun, address: str,
        observation_type: str, method: str, outcome: str, data: dict[str, str],
    ) -> None:
        from redforge.domain.inventory.identity import build_external_id

        ip_external_id = build_external_id(IdentityScheme.IP_ADDRESS, address)
        async with self._session_factory() as session:
            from redforge.infrastructure.database.repositories.asset_repository import (
                SqlAlchemyAssetRepository,
            )

            asset_repo = SqlAlchemyAssetRepository(session)
            ip_asset = await asset_repo.get_by_external_id(organization_id, ip_external_id)
            asset_id = str(ip_asset.id) if ip_asset is not None else str(run.target_asset_id)

            obs_repo = SqlAlchemyNetworkObservationRepository(session)
            await obs_repo.append(
                organization_id=organization_id, run_id=str(run.id), asset_id=asset_id,
                observation_type=observation_type, method=method, outcome=outcome, data=data,
                observed_at=datetime.now(UTC),
            )
            await session.commit()

    def _to_dto(
        self, run: NetworkValidationRun, reachable_ports: list[int], denied_addresses: list[str],
    ) -> NetworkValidationRunDTO:
        return NetworkValidationRunDTO(
            id=str(run.id), organization_id=str(run.organization_id),
            target_asset_id=str(run.target_asset_id), profile=str(run.profile),
            status=str(run.status),
            authorization_id=str(run.authorization_id) if run.authorization_id else None,
            failure_reason="", reachable_ports=reachable_ports,
            denied_addresses=denied_addresses,
        )


def _identity_key_for_port(port: int) -> str:
    return f"port:{port}"


def _detect_drift(
    previous: NetworkStateSnapshot | None, current: NetworkStateSnapshot,
    reactivated_keys: frozenset[str] = frozenset(),
) -> list[NetworkDriftEvent]:
    """Deterministic diff — identical semantics to M14's own
    detect_drift(): zero fabricated drift on a first-ever run (no
    previous snapshot), zero drift when content_fingerprint matches.
    `reactivated_keys` (from `_compute_reactivated_keys`) reclassifies
    a subset of newly-active condition keys as CONDITION_REACTIVATED
    instead of CONDITION_APPEARED."""
    if previous is None:
        return []
    if previous.is_identical_to(current):
        return []

    events: list[NetworkDriftEvent] = []

    def _add(category: SecurityDriftCategory, identity_key: str, summary: str) -> None:
        if category not in NETWORK_DRIFT_CATEGORIES:
            return
        events.append(
            NetworkDriftEvent.create(
                organization_id=current.organization_id, policy_id=current.policy_id,
                run_id=current.run_id, category=category, identity_key=identity_key,
                summary=summary,
            )
        )

    prev_ips, cur_ips = set(previous.resolved_ips), set(current.resolved_ips)
    for ip in sorted(cur_ips - prev_ips):
        _add(SecurityDriftCategory.IP_OBSERVED, f"ip:{ip}", f"IP address {ip} observed.")
    for ip in sorted(prev_ips - cur_ips):
        _add(
            SecurityDriftCategory.IP_NO_LONGER_OBSERVED, f"ip:{ip}",
            f"IP address {ip} was not observed during revalidation.",
        )

    prev_ports, cur_ports = set(previous.reachable_ports), set(current.reachable_ports)
    for port in sorted(cur_ports - prev_ports):
        _add(
            SecurityDriftCategory.PORT_BECAME_REACHABLE, _identity_key_for_port(port),
            f"{port}/tcp became reachable.",
        )
    for port in sorted(prev_ports - cur_ports):
        _add(
            SecurityDriftCategory.PORT_NO_LONGER_REACHABLE, _identity_key_for_port(port),
            f"{port}/tcp was not observed during revalidation.",
        )

    prev_services = {s.port: s for s in previous.services}
    cur_services = {s.port: s for s in current.services}
    for port, cur_svc in cur_services.items():
        prev_svc = prev_services.get(port)
        if prev_svc is None:
            if cur_svc.validated_protocol:
                _add(
                    SecurityDriftCategory.PROTOCOL_VALIDATED, f"protocol:{port}",
                    f"{cur_svc.validated_protocol} validated on {port}/tcp.",
                )
            continue
        if prev_svc.validated_protocol and not cur_svc.validated_protocol:
            _add(
                SecurityDriftCategory.PROTOCOL_NO_LONGER_VALIDATED, f"protocol:{port}",
                f"Protocol no longer validated on {port}/tcp.",
            )
        elif (
            cur_svc.validated_protocol
            and prev_svc.validated_protocol != cur_svc.validated_protocol
        ):
            _add(
                SecurityDriftCategory.PROTOCOL_CHANGED, f"protocol:{port}",
                f"Protocol changed from {prev_svc.validated_protocol} to "
                f"{cur_svc.validated_protocol} on {port}/tcp.",
            )
        if (
            cur_svc.tls_fingerprint_sha256
            and prev_svc.tls_fingerprint_sha256
            and cur_svc.tls_fingerprint_sha256 != prev_svc.tls_fingerprint_sha256
        ):
            _add(
                SecurityDriftCategory.TLS_CERTIFICATE_CHANGED, f"tls:{port}",
                f"TLS certificate changed on {port}/tcp.",
            )

    prev_conditions, cur_conditions = (
        set(previous.active_condition_keys), set(current.active_condition_keys),
    )
    for key in sorted(cur_conditions - prev_conditions):
        if key in reactivated_keys:
            _add(
                SecurityDriftCategory.CONDITION_REACTIVATED, f"condition:{key}",
                "Condition reactivated.",
            )
        else:
            _add(
                SecurityDriftCategory.CONDITION_APPEARED, f"condition:{key}",
                "Condition appeared.",
            )
    for key in sorted(prev_conditions - cur_conditions):
        _add(SecurityDriftCategory.CONDITION_RESOLVED, f"condition:{key}", "Condition resolved.")

    prev_correlations, cur_correlations = (
        set(previous.active_correlation_keys), set(current.active_correlation_keys),
    )
    for key in sorted(cur_correlations - prev_correlations):
        _add(
            SecurityDriftCategory.CORRELATION_APPEARED, f"correlation:{key}",
            "Correlation appeared.",
        )
    for key in sorted(prev_correlations - cur_correlations):
        _add(
            SecurityDriftCategory.CORRELATION_RESOLVED, f"correlation:{key}",
            "Correlation resolved.",
        )

    return events


def _compute_reactivated_keys(
    previous: NetworkStateSnapshot | None,
    current: NetworkStateSnapshot,
    first_observed_by_key: dict[str, str],
) -> frozenset[str]:
    """A newly-active condition identity key is a REACTIVATION (rather
    than a fresh APPEARANCE) only when its own first_observed_at
    predates the previous snapshot's own captured_at — i.e. the row
    already existed, and therefore must have been resolved as of the
    previous comparison (it was not in that snapshot's active set), and
    is active again now. Mirrors
    application/continuous_validation/processor.py's own
    `_compute_reactivated_keys()` exactly."""
    if previous is None:
        return frozenset()

    previous_active = set(previous.active_condition_keys)
    current_active = set(current.active_condition_keys)
    newly_active = current_active - previous_active
    if not newly_active:
        return frozenset()

    previous_captured_at = previous.captured_at
    if previous_captured_at.tzinfo is None:
        previous_captured_at = previous_captured_at.replace(tzinfo=UTC)

    reactivated = set()
    for key in newly_active:
        first_observed = first_observed_by_key.get(key)
        if not first_observed:
            continue
        try:
            first_observed_dt = datetime.fromisoformat(first_observed)
        except ValueError:
            continue
        if first_observed_dt.tzinfo is None:
            first_observed_dt = first_observed_dt.replace(tzinfo=UTC)
        if first_observed_dt < previous_captured_at:
            reactivated.add(key)
    return frozenset(reactivated)
