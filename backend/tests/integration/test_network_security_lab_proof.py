"""Owned local network-security lab + real-PostgreSQL end-to-end proof
for M16 — Advanced Network Security & Continuous Network Monitoring.

Runs against a dedicated, pre-migrated database
(`redforge_network_security_proof_test`), never the shared dev database.
LOOPBACK ONLY — a bare, self-owned TCP listener on 127.0.0.1, never an
external/LAN/internet target.

Proves:
  1. An unauthorized loopback IP is denied (NO_MATCHING_AUTHORIZATION) —
     zero probes occur.
  2. An authorized loopback IP with a reachable owned TCP listener is
     observed: NetworkValidationRun COMPLETED, IP_ADDRESS/HOST/SERVICE
     AIAssets resolved, a NetworkObservation persisted, correlation
     evaluation runs without error.
  3. Revoking the authorization blocks the next run
     (NO_MATCHING_AUTHORIZATION again — fresh, uncached check).
  4. Stopping the owned listener and revalidating produces
     PORT_NO_LONGER_REACHABLE drift against the continuous policy;
     restarting it produces PORT_BECAME_REACHABLE on the following run.
  5. An identical repeated run produces zero new drift (snapshot
     content-fingerprint fast path).
  6. A CIDR adjacent to (but excluding) the authorized IP is denied.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.network_security.orchestrator import NetworkValidationOrchestrator
from redforge.application.security_conditions.service import TenantSecurityConditionService
from redforge.application.security_correlation.rules import (
    CorrelationRuleRegistry,
    MultipleSecurityConditionsOnAssetRule,
    PublicSensitiveServiceContextRule,
)
from redforge.application.security_correlation.service import TenantSecurityCorrelationService
from redforge.domain.authorization.entity import SecurityAuthorization
from redforge.domain.authorization.value_objects import (
    ActionClass,
    AuthorizationScopeEntry,
    ScopeEntityType,
    ValidityWindow,
)
from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import AssetDiscoverySource, AssetType
from redforge.domain.network_security.value_objects import (
    NetworkRunStatus,
    NetworkValidationProfile,
    ValidationCadence,
)
from redforge.infrastructure.database.repositories.authorization.repository import (
    SqlAlchemySecurityAuthorizationRepository,
)
from redforge.infrastructure.database.repositories.network_security.drift_repository import (
    SqlAlchemyNetworkDriftEventRepository,
)
from redforge.infrastructure.database.repositories.network_security.observation_repository import (
    SqlAlchemyNetworkObservationRepository,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

pytestmark = pytest.mark.asyncio

_TEST_DB_NAME = "redforge_network_security_proof_test"
_DB_URL = os.environ.get(
    "REDFORGE_TEST_DATABASE_URL",
    f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_TEST_DB_NAME}",
)
_LAB_PORT = 8080  # in planner._COMMON_SERVICE_PORTS territory (NETWORK_STANDARD)


def _assert_isolated_proof_database(target_db_name: str) -> None:
    print(f"[proof-db-guard] destructive command target database: {target_db_name!r}")
    assert target_db_name == _TEST_DB_NAME, (
        f"REFUSING destructive command: target database {target_db_name!r} is not the "
        f"isolated proof database {_TEST_DB_NAME!r}"
    )


class _OwnedTcpListener:
    """A bare, deterministic, start/stoppable TCP listener bound to
    127.0.0.1 — never a real service, never anything beyond accepting
    and immediately closing connections."""

    def __init__(self, port: int) -> None:
        self._port = port
        self._sock: socket.socket | None = None

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", self._port))
        sock.listen(5)
        sock.setblocking(False)
        self._sock = sock

    def stop(self) -> None:
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._sock.close()
            self._sock = None


@pytest.fixture
async def session_factory():
    _assert_isolated_proof_database(_TEST_DB_NAME)
    engine = create_async_engine(_DB_URL, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.fixture
def lab_listener():
    listener = _OwnedTcpListener(_LAB_PORT)
    listener.start()
    yield listener
    listener.stop()


async def _authorize_ip(
    session_factory, organization_id: str, requester_user_id: str, approver_user_id: str,
    ip_asset_id: str,
) -> str:
    authorization = SecurityAuthorization.create(
        organization_id=EntityId.from_string(organization_id),
        requester_user_id=EntityId.from_string(requester_user_id),
        validity=ValidityWindow(
            valid_from=utc_now(), valid_until=utc_now().replace(year=utc_now().year + 1),
        ),
        action_classes={ActionClass.ACTIVE_VALIDATION},
        scope={AuthorizationScopeEntry(entity_type=ScopeEntityType.AI_ASSET, entity_id=ip_asset_id)},
    )
    authorization.submit_for_approval()
    authorization.approve(EntityId.from_string(approver_user_id))
    async with session_factory() as session:
        repo = SqlAlchemySecurityAuthorizationRepository(session)
        await repo.save(authorization)
        await session.commit()
    return str(authorization.id)


async def _revoke(session_factory, organization_id: str, authorization_id: str) -> None:
    async with session_factory() as session:
        repo = SqlAlchemySecurityAuthorizationRepository(session)
        authorization = await repo.get_by_id_for_organization(
            EntityId.from_string(authorization_id), EntityId.from_string(organization_id),
        )
        assert authorization is not None
        authorization.revoke(EntityId.from_string(organization_id))
        await repo.save(authorization)
        await session.commit()


def _build_orchestrator(session_factory) -> NetworkValidationOrchestrator:
    asset_service = TenantAssetService(session_factory)
    condition_service = TenantSecurityConditionService(session_factory)
    registry = CorrelationRuleRegistry()
    registry.register(PublicSensitiveServiceContextRule(asset_service, condition_service))
    registry.register(MultipleSecurityConditionsOnAssetRule(condition_service))
    correlation_service = TenantSecurityCorrelationService(session_factory, registry)
    return NetworkValidationOrchestrator(
        session_factory, asset_service, condition_service, correlation_service,
    )


async def test_network_security_owned_loopback_lab(session_factory, lab_listener) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    approver_id = str(EntityId.generate())

    asset_service = TenantAssetService(session_factory)
    orchestrator = _build_orchestrator(session_factory)

    # ─── Step 1: create the IP_ADDRESS asset (unauthorized) ────────────────
    ip_asset = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.IP_ADDRESS,
        scheme=IdentityScheme.IP_ADDRESS, raw_external_id="127.0.0.1",
        name="127.0.0.1", description="Owned loopback lab target",
        discovery_source=AssetDiscoverySource.API_SCAN,
    )

    # ─── Step 2: unauthorized run is denied, zero probes ───────────────────
    denied_run = await orchestrator.create_and_run(
        organization_id=org_id, target_asset_id=ip_asset.id, requester_user_id=requester_id,
        profile=NetworkValidationProfile.NETWORK_DEEP_SAFE,
    )
    assert denied_run.status == str(NetworkRunStatus.DENIED)
    assert denied_run.reachable_ports == []

    # ─── Step 3: authorize, then run again — observed + COMPLETED ──────────
    authorization_id = await _authorize_ip(
        session_factory, org_id, requester_id, approver_id, ip_asset.id,
    )
    run1 = await orchestrator.create_and_run(
        organization_id=org_id, target_asset_id=ip_asset.id, requester_user_id=requester_id,
        profile=NetworkValidationProfile.NETWORK_DEEP_SAFE,
    )
    assert run1.status == str(NetworkRunStatus.COMPLETED)
    assert _LAB_PORT in run1.reachable_ports
    assert run1.authorization_id == authorization_id

    async with session_factory() as session:
        obs_repo = SqlAlchemyNetworkObservationRepository(session)
        observations = await obs_repo.list_for_run(org_id, run1.id)
    assert any(o.observation_type == "tcp_reachability" for o in observations)
    # No raw secrets/banners in persisted observation data.
    serialized = str(observations)
    for sentinel in (
        "Authorization:", "Cookie:", "BEGIN PRIVATE KEY", "password",
        "Bearer ", "bearer ", "api_key", "secret_key", "client_secret",
        "-----BEGIN", "set-cookie",
    ):
        assert sentinel not in serialized

    ip_asset_check = await asset_service.get_for_org(ip_asset.id, org_id)
    assert ip_asset_check.asset_type == "ip_address"

    # ─── Step 4: adjacent CIDR is NOT authorized (scope precision) ─────────
    network_asset = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.NETWORK,
        scheme=IdentityScheme.NETWORK_CIDR, raw_external_id="127.0.0.2/32",
        name="127.0.0.2/32", description="Adjacent, unauthorized network",
        discovery_source=AssetDiscoverySource.API_SCAN,
    )
    adjacent_run = await orchestrator.create_and_run(
        organization_id=org_id, target_asset_id=network_asset.id,
        requester_user_id=requester_id, profile=NetworkValidationProfile.NETWORK_DEEP_SAFE,
    )
    assert adjacent_run.status == str(NetworkRunStatus.DENIED)

    # ─── Step 5: revoke authorization -> next run is denied again ──────────
    await _revoke(session_factory, org_id, authorization_id)
    revoked_run = await orchestrator.create_and_run(
        organization_id=org_id, target_asset_id=ip_asset.id, requester_user_id=requester_id,
        profile=NetworkValidationProfile.NETWORK_DEEP_SAFE,
    )
    assert revoked_run.status == str(NetworkRunStatus.DENIED)

    # Re-authorize for the continuous-policy drift proof below.
    authorization_id_2 = await _authorize_ip(
        session_factory, org_id, requester_id, approver_id, ip_asset.id,
    )
    assert authorization_id_2 != authorization_id


async def test_network_security_continuous_drift(session_factory, lab_listener) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    approver_id = str(EntityId.generate())

    asset_service = TenantAssetService(session_factory)
    orchestrator = _build_orchestrator(session_factory)

    ip_asset = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.IP_ADDRESS,
        scheme=IdentityScheme.IP_ADDRESS, raw_external_id="127.0.0.1",
        name="127.0.0.1", description="Owned loopback lab target (drift)",
        discovery_source=AssetDiscoverySource.API_SCAN,
    )
    await _authorize_ip(session_factory, org_id, requester_id, approver_id, ip_asset.id)

    from redforge.application.network_security.policy_service import (
        NetworkMonitoringPolicyService,
    )

    policy_service = NetworkMonitoringPolicyService(session_factory)
    policy = await policy_service.create(
        organization_id=org_id, target_asset_id=ip_asset.id, requester_user_id=requester_id,
        profile=NetworkValidationProfile.NETWORK_DEEP_SAFE, cadence=ValidationCadence.HOURLY,
    )
    await policy_service.activate(policy.id, org_id)

    # Baseline run: listener up, port reachable -> first snapshot, zero drift
    # (no prior snapshot to differ against).
    baseline = await orchestrator.create_and_run(
        organization_id=org_id, target_asset_id=ip_asset.id, requester_user_id=requester_id,
        profile=NetworkValidationProfile.NETWORK_DEEP_SAFE, trigger="on_demand",
        continuous_policy_id=policy.id,
    )
    assert baseline.status == str(NetworkRunStatus.COMPLETED)
    assert _LAB_PORT in baseline.reachable_ports

    async with session_factory() as session:
        drift_repo = SqlAlchemyNetworkDriftEventRepository(session)
        baseline_drift = await drift_repo.list_for_policy(
            EntityId.from_string(policy.id), EntityId.from_string(org_id), 100, 0,
        )
    assert baseline_drift == []

    # Identical rerun -> zero NEW drift.
    rerun = await orchestrator.create_and_run(
        organization_id=org_id, target_asset_id=ip_asset.id, requester_user_id=requester_id,
        profile=NetworkValidationProfile.NETWORK_DEEP_SAFE, trigger="on_demand",
        continuous_policy_id=policy.id,
    )
    assert rerun.status == str(NetworkRunStatus.COMPLETED)
    async with session_factory() as session:
        drift_repo = SqlAlchemyNetworkDriftEventRepository(session)
        rerun_drift = await drift_repo.list_for_policy(
            EntityId.from_string(policy.id), EntityId.from_string(org_id), 100, 0,
        )
    assert rerun_drift == []

    # Stop the listener -> revalidate -> PORT_NO_LONGER_REACHABLE drift.
    lab_listener.stop()
    await asyncio.sleep(0.1)
    stopped_run = await orchestrator.create_and_run(
        organization_id=org_id, target_asset_id=ip_asset.id, requester_user_id=requester_id,
        profile=NetworkValidationProfile.NETWORK_DEEP_SAFE, trigger="on_demand",
        continuous_policy_id=policy.id,
    )
    assert _LAB_PORT not in stopped_run.reachable_ports
    async with session_factory() as session:
        drift_repo = SqlAlchemyNetworkDriftEventRepository(session)
        drift_after_stop = await drift_repo.list_for_policy(
            EntityId.from_string(policy.id), EntityId.from_string(org_id), 100, 0,
        )
    categories = {str(d.category) for d in drift_after_stop}
    assert "port_no_longer_reachable" in categories

    # Restart the listener -> revalidate -> PORT_BECAME_REACHABLE drift.
    lab_listener.start()
    restarted_run = await orchestrator.create_and_run(
        organization_id=org_id, target_asset_id=ip_asset.id, requester_user_id=requester_id,
        profile=NetworkValidationProfile.NETWORK_DEEP_SAFE, trigger="on_demand",
        continuous_policy_id=policy.id,
    )
    assert _LAB_PORT in restarted_run.reachable_ports
    async with session_factory() as session:
        drift_repo = SqlAlchemyNetworkDriftEventRepository(session)
        drift_after_restart = await drift_repo.list_for_policy(
            EntityId.from_string(policy.id), EntityId.from_string(org_id), 100, 0,
        )
    categories_after_restart = {str(d.category) for d in drift_after_restart}
    assert "port_became_reachable" in categories_after_restart


async def test_probe_concurrency_never_exceeds_max_concurrency_bound(session_factory) -> None:
    """Regression test for a real defect found during independent
    security review: the per-address authorization re-check
    (`_reverify_address`) previously ran OUTSIDE the MAX_CONCURRENCY
    semaphore, so a large plan could open hundreds of concurrent DB
    sessions at once. Fixed by moving the semaphore to wrap the ENTIRE
    probe body. This test instruments `_reverify_address` to record
    the maximum number of concurrently in-flight calls during a real
    multi-address, multi-port NETWORK_DEEP_SAFE run and asserts it
    never exceeds the orchestrator's own MAX_CONCURRENCY bound."""
    import redforge.application.network_security.orchestrator as orchestrator_module

    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    approver_id = str(EntityId.generate())

    asset_service = TenantAssetService(session_factory)
    orchestrator = _build_orchestrator(session_factory)

    # A small, bounded authorized network (127.0.0.0/29 -> 6 usable
    # loopback addresses) so the plan fans out across multiple
    # addresses x ports without needing an external network.
    network_asset = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.NETWORK,
        scheme=IdentityScheme.NETWORK_CIDR, raw_external_id="127.0.0.0/29",
        name="127.0.0.0/29", description="Owned loopback lab range (concurrency proof)",
        discovery_source=AssetDiscoverySource.API_SCAN,
    )
    authorization_id = await _authorize_ip(
        session_factory, org_id, requester_id, approver_id, network_asset.id,
    )
    assert authorization_id

    in_flight = 0
    max_in_flight = 0
    original_reverify = orchestrator._reverify_address

    async def _tracked_reverify(organization_id: str, address: str) -> bool:
        nonlocal in_flight, max_in_flight
        in_flight += 1
        max_in_flight = max(max_in_flight, in_flight)
        try:
            return await original_reverify(organization_id, address)
        finally:
            in_flight -= 1

    orchestrator._reverify_address = _tracked_reverify  # type: ignore[method-assign]

    run = await orchestrator.create_and_run(
        organization_id=org_id, target_asset_id=network_asset.id, requester_user_id=requester_id,
        profile=orchestrator_module.NetworkValidationProfile.NETWORK_DEEP_SAFE,
    )
    assert run.status in ("completed", "partially_completed")
    assert max_in_flight <= orchestrator_module.MAX_CONCURRENCY
    assert max_in_flight > 1  # sanity: the run was genuinely concurrent, not accidentally serial


async def test_execution_deadline_stops_scheduling_new_probes(
    session_factory, lab_listener,
) -> None:
    """Scenario #52: once the run's EXECUTION_DEADLINE_SECONDS has
    elapsed, no NEW probe starts — proven by forcing the deadline to
    an already-elapsed value (monkeypatched to 0) against a real
    multi-address authorized network, so every probe attempt must see
    `loop.time() >= deadline` and return immediately without ever
    calling check_tcp_connectivity."""
    import redforge.application.network_security.orchestrator as orchestrator_module

    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    approver_id = str(EntityId.generate())

    asset_service = TenantAssetService(session_factory)
    orchestrator = _build_orchestrator(session_factory)

    network_asset = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.NETWORK,
        scheme=IdentityScheme.NETWORK_CIDR, raw_external_id="127.0.0.0/29",
        name="127.0.0.0/29", description="Owned loopback lab range (deadline proof)",
        discovery_source=AssetDiscoverySource.API_SCAN,
    )
    await _authorize_ip(session_factory, org_id, requester_id, approver_id, network_asset.id)

    original_deadline = orchestrator_module.EXECUTION_DEADLINE_SECONDS
    orchestrator_module.EXECUTION_DEADLINE_SECONDS = 0.0
    try:
        run = await orchestrator.create_and_run(
            organization_id=org_id, target_asset_id=network_asset.id,
            requester_user_id=requester_id,
            profile=orchestrator_module.NetworkValidationProfile.NETWORK_DEEP_SAFE,
        )
    finally:
        orchestrator_module.EXECUTION_DEADLINE_SECONDS = original_deadline

    # With a zero deadline, every probe attempt returns immediately —
    # no port can ever be observed reachable, even though the owned lab
    # listener is genuinely up.
    assert run.reachable_ports == []
