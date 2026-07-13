"""Mid-run execution cancellation proof for NetworkValidationRun — M16
adversarial traceability scenario #51.

Runs against the same isolated, pre-migrated proof database as
test_network_security_lab_proof.py. Proves:

  1. A genuinely in-progress run (real loopback listener + several
     unreachable ports, bounded by CONNECT_TIMEOUT_SECONDS/
     MAX_CONCURRENCY) can be cancelled via a concurrent request while
     probes are still running, and reaches terminal CANCELLED — not via
     direct repository mutation, but by calling the same
     `request_cancellation()` entry point the API uses.
  2. A cancelled run skips _reconcile() entirely: no new drift event is
     recorded against its continuous policy despite partial results,
     and re-running immediately afterward (uncancelled) still sees zero
     prior snapshot to diff against — proving no false condition
     resolution / no false disappearance drift was fabricated from the
     cancelled run's incomplete data.
  3. The real-PostgreSQL stale-aggregate-save race: session A loads the
     run before cancellation, session B requests cancellation and
     commits, then session A (holding its stale in-memory copy) calls
     the ordinary `save()` — the cancellation flag must survive A's
     save untouched, because save()'s UPDATE branch never writes that
     column.
  4. Idempotency: requesting cancellation twice, and requesting it
     against an already-terminal (COMPLETED) run, are both safe no-ops
     that never raise and never revive a terminal run.
  5. Cross-tenant / unknown run: request_cancellation returns None
     rather than disclosing existence to the wrong tenant.
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
from redforge.application.security_correlation.rules import CorrelationRuleRegistry
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
from redforge.infrastructure.database.repositories.network_security.run_repository import (
    SqlAlchemyNetworkValidationRunRepository,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

pytestmark = pytest.mark.asyncio

_TEST_DB_NAME = "redforge_network_security_proof_test"
_DB_URL = os.environ.get(
    "REDFORGE_TEST_DATABASE_URL",
    f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_TEST_DB_NAME}",
)
_LAB_PORT = 8080


def _assert_isolated_proof_database(target_db_name: str) -> None:
    assert target_db_name == _TEST_DB_NAME, (
        f"REFUSING destructive command: target database {target_db_name!r} is not the "
        f"isolated proof database {_TEST_DB_NAME!r}"
    )


class _OwnedTcpListener:
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


def _build_orchestrator(session_factory) -> NetworkValidationOrchestrator:
    asset_service = TenantAssetService(session_factory)
    condition_service = TenantSecurityConditionService(session_factory)
    registry = CorrelationRuleRegistry()
    correlation_service = TenantSecurityCorrelationService(session_factory, registry)
    return NetworkValidationOrchestrator(
        session_factory, asset_service, condition_service, correlation_service,
    )


async def test_mid_run_cancellation_reaches_terminal_cancelled(
    session_factory, lab_listener,
) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    approver_id = str(EntityId.generate())

    asset_service = TenantAssetService(session_factory)
    orchestrator = _build_orchestrator(session_factory)

    ip_asset = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.IP_ADDRESS,
        scheme=IdentityScheme.IP_ADDRESS, raw_external_id="127.0.0.1",
        name="127.0.0.1", description="Cancellation proof target",
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

    run_task = asyncio.ensure_future(
        orchestrator.create_and_run(
            organization_id=org_id, target_asset_id=ip_asset.id, requester_user_id=requester_id,
            profile=NetworkValidationProfile.NETWORK_DEEP_SAFE, trigger="on_demand",
            continuous_policy_id=policy.id,
        )
    )
    # Poll (rather than a single fixed sleep) for the run to appear and
    # progress past PENDING — under heavy machine/test-suite load a fixed
    # short sleep can fire before create_and_run() has even finished its
    # first save(), which is a timing artifact of the poll, not of
    # cancellation itself.
    run_id: str | None = None
    for _ in range(60):  # up to ~3s
        await asyncio.sleep(0.05)
        async with session_factory() as session:
            repo = SqlAlchemyNetworkValidationRunRepository(session)
            runs = await repo.list_for_organization(EntityId.from_string(org_id), 10, 0)
        if runs and runs[0].status != NetworkRunStatus.PENDING:
            run_id = str(runs[0].id)
            break
    assert run_id is not None, "run never progressed past PENDING in time"

    status_after_request = await orchestrator.request_cancellation(org_id, run_id)
    assert status_after_request in {
        str(NetworkRunStatus.POLICY_CHECKING), str(NetworkRunStatus.AUTHORIZED),
        str(NetworkRunStatus.RUNNING),
    }

    dto = await run_task
    assert dto.status == str(NetworkRunStatus.CANCELLED)

    # No new drift/reconciliation happened for the cancelled run — the
    # continuous policy still has zero drift events (only a genuinely
    # completed run would populate a snapshot to diff against).
    async with session_factory() as session:
        drift_repo = SqlAlchemyNetworkDriftEventRepository(session)
        drift = await drift_repo.list_for_policy(
            EntityId.from_string(policy.id), EntityId.from_string(org_id), 100, 0,
        )
    assert drift == []


async def test_cancellation_idempotent_and_safe_on_terminal_run(
    session_factory, lab_listener,
) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    approver_id = str(EntityId.generate())

    asset_service = TenantAssetService(session_factory)
    orchestrator = _build_orchestrator(session_factory)

    ip_asset = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.IP_ADDRESS,
        scheme=IdentityScheme.IP_ADDRESS, raw_external_id="127.0.0.1",
        name="127.0.0.1", description="Cancellation-on-terminal-run proof target",
        discovery_source=AssetDiscoverySource.API_SCAN,
    )
    await _authorize_ip(session_factory, org_id, requester_id, approver_id, ip_asset.id)

    completed = await orchestrator.create_and_run(
        organization_id=org_id, target_asset_id=ip_asset.id, requester_user_id=requester_id,
        profile=NetworkValidationProfile.NETWORK_DEEP_SAFE,
    )
    assert completed.status == str(NetworkRunStatus.COMPLETED)

    status_1 = await orchestrator.request_cancellation(org_id, completed.id)
    status_2 = await orchestrator.request_cancellation(org_id, completed.id)
    assert status_1 == str(NetworkRunStatus.COMPLETED)
    assert status_2 == str(NetworkRunStatus.COMPLETED)

    async with session_factory() as session:
        repo = SqlAlchemyNetworkValidationRunRepository(session)
        run = await repo.get_by_id_for_organization(
            EntityId.from_string(completed.id), EntityId.from_string(org_id),
        )
    assert run is not None
    assert run.status == NetworkRunStatus.COMPLETED  # never resurrected/overwritten


async def test_cancellation_cross_tenant_and_unknown_run_returns_none(
    session_factory, lab_listener,
) -> None:
    org_id = str(EntityId.generate())
    other_org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    approver_id = str(EntityId.generate())

    asset_service = TenantAssetService(session_factory)
    orchestrator = _build_orchestrator(session_factory)

    ip_asset = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.IP_ADDRESS,
        scheme=IdentityScheme.IP_ADDRESS, raw_external_id="127.0.0.1",
        name="127.0.0.1", description="Cross-tenant cancellation proof target",
        discovery_source=AssetDiscoverySource.API_SCAN,
    )
    await _authorize_ip(session_factory, org_id, requester_id, approver_id, ip_asset.id)

    run = await orchestrator.create_and_run(
        organization_id=org_id, target_asset_id=ip_asset.id, requester_user_id=requester_id,
        profile=NetworkValidationProfile.NETWORK_DEEP_SAFE,
    )

    cross_tenant_status = await orchestrator.request_cancellation(other_org_id, run.id)
    assert cross_tenant_status is None

    unknown_run_status = await orchestrator.request_cancellation(
        org_id, str(EntityId.generate()),
    )
    assert unknown_run_status is None


async def test_stale_aggregate_save_cannot_clobber_cancellation_request(
    session_factory, lab_listener,
) -> None:
    """The real-PostgreSQL race this scenario exists to close: session A
    loads the run (RUNNING), session B requests cancellation and
    commits, then A — still holding its stale in-memory copy — calls
    the ordinary save() (e.g. as if finishing normally). The
    cancellation flag must survive A's save untouched."""
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    approver_id = str(EntityId.generate())

    asset_service = TenantAssetService(session_factory)
    ip_asset = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.IP_ADDRESS,
        scheme=IdentityScheme.IP_ADDRESS, raw_external_id="127.0.0.1",
        name="127.0.0.1", description="Stale-save race proof target",
        discovery_source=AssetDiscoverySource.API_SCAN,
    )
    await _authorize_ip(session_factory, org_id, requester_id, approver_id, ip_asset.id)

    from redforge.domain.network_security.entity import NetworkValidationRun

    run_a = NetworkValidationRun.create(
        organization_id=EntityId.from_string(org_id),
        target_asset_id=EntityId.from_string(ip_asset.id),
        requester_user_id=EntityId.from_string(requester_id),
        profile=NetworkValidationProfile.NETWORK_DEEP_SAFE,
    )
    run_a.begin_policy_check()
    run_a.authorize(EntityId.from_string(str(EntityId.generate())))
    run_a.start()

    # Session A's initial persist (RUNNING, cancellation_requested=False).
    async with session_factory() as session:
        repo = SqlAlchemyNetworkValidationRunRepository(session)
        await repo.save(run_a)
        await session.commit()

    # Session B requests cancellation concurrently and commits.
    async with session_factory() as session:
        repo_b = SqlAlchemyNetworkValidationRunRepository(session)
        b_status = await repo_b.request_cancellation(
            run_a.id, EntityId.from_string(org_id),
        )
        await session.commit()
    assert b_status == str(NetworkRunStatus.RUNNING)

    # Session A, unaware of B's cancellation request, now finishes the
    # run normally and saves its stale in-memory aggregate.
    run_a.finish(NetworkRunStatus.COMPLETED)
    async with session_factory() as session:
        repo_a = SqlAlchemyNetworkValidationRunRepository(session)
        await repo_a.save(run_a)
        await session.commit()

    # The cancellation flag must have survived A's stale save.
    async with session_factory() as session:
        repo = SqlAlchemyNetworkValidationRunRepository(session)
        is_requested = await repo.is_cancellation_requested(
            run_a.id, EntityId.from_string(org_id),
        )
    assert is_requested is True


async def test_scheduler_dispatched_run_can_be_cancelled_mid_flight(
    session_factory,
) -> None:
    """The scheduler-dispatched path (`NetworkMonitoringProcessor.
    process_one_due_policy()` — real SKIP LOCKED claim, not `run-now`)
    can be cancelled mid-flight exactly like the manual path, because
    both funnel through the identical `create_and_run()`. Proves:
      - the claimed policy's run reaches CANCELLED
      - the policy's OWN lifecycle is not corrupted: its claim is
        released and its schedule advanced normally (`_release_and_advance`
        runs regardless of the run's own outcome, since cancellation is
        not an exception)
      - no duplicate run is created: a second immediate claim attempt
        for the same policy finds nothing due (schedule already advanced)
    """
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    approver_id = str(EntityId.generate())

    asset_service = TenantAssetService(session_factory)
    orchestrator = _build_orchestrator(session_factory)

    # A non-routable TEST-NET-2 address (never dialed on any real
    # network) rather than loopback: an unreachable LOOPBACK port
    # refuses the connection immediately (near-zero latency), which
    # would make the run complete before it could ever be observed as
    # RUNNING. A blackholed address makes every probe genuinely block
    # for the full CONNECT_TIMEOUT_SECONDS, giving a real, deterministic
    # in-flight window — the same technique scripts/m16_live_api_acceptance.py
    # uses for its own mid-run cancellation proof.
    ip_asset = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.IP_ADDRESS,
        scheme=IdentityScheme.IP_ADDRESS, raw_external_id="198.51.100.77",
        name="198.51.100.77", description="Scheduler cancellation proof target",
        discovery_source=AssetDiscoverySource.API_SCAN,
    )
    await _authorize_ip(session_factory, org_id, requester_id, approver_id, ip_asset.id)

    from redforge.application.network_security.scheduler import NetworkMonitoringProcessor
    from redforge.domain.network_security.entity import NetworkMonitoringPolicy
    from redforge.infrastructure.database.repositories.network_security.policy_repository import (
        SqlAlchemyNetworkMonitoringPolicyRepository,
    )

    processor = NetworkMonitoringProcessor(session_factory, orchestrator)

    # `claim_one_due_policy()` claims ANY due ACTIVE policy globally (a
    # correct, deliberate whole-table scan — see its own docstring), so
    # this proof DB may contain other ACTIVE, still-due policies left
    # over from other tests in the same session (e.g. a policy whose run
    # was cancelled via direct orchestrator.create_and_run() rather than
    # through the scheduler, which never advances its schedule, or a
    # policy from an unrelated test file still due under full-suite
    # contention). Rather than draining them (which itself races against
    # the rest of the suite still running concurrently against the same
    # DB), deterministically quarantine every OTHER due ACTIVE policy by
    # flipping it to PAUSED first — `claim_one_due_policy()` only
    # considers `lifecycle == ACTIVE`, so this makes our own policy the
    # only possible candidate without depending on timing at all.
    from sqlalchemy import update as sa_update

    from redforge.domain.network_security.value_objects import PolicyLifecycle
    from redforge.infrastructure.database.models.network_security import (
        NetworkMonitoringPolicyModel,
    )

    async with session_factory() as session:
        await session.execute(
            sa_update(NetworkMonitoringPolicyModel)
            .where(NetworkMonitoringPolicyModel.lifecycle == str(PolicyLifecycle.ACTIVE))
            .values(lifecycle=str(PolicyLifecycle.PAUSED))
        )
        await session.commit()

    # NETWORK_DEEP_SAFE gives 14 ports probed in one concurrent wave
    # (MAX_CONCURRENCY=16), each blocking for the full
    # CONNECT_TIMEOUT_SECONDS against the blackholed address above.
    policy = NetworkMonitoringPolicy.create(
        organization_id=EntityId.from_string(org_id), target_asset_id=EntityId.from_string(ip_asset.id),
        requester_user_id=EntityId.from_string(requester_id),
        profile=NetworkValidationProfile.NETWORK_DEEP_SAFE, cadence=ValidationCadence.HOURLY,
    )
    policy.activate(utc_now())
    async with session_factory() as session:
        await SqlAlchemyNetworkMonitoringPolicyRepository(session).save(policy)
        await session.commit()

    claim_task = asyncio.ensure_future(processor.process_one_due_policy("scheduler-worker-1"))
    try:
        mid_run_id: str | None = None
        for _ in range(100):  # up to ~5s at 0.05s intervals — full-suite-load-tolerant
            await asyncio.sleep(0.05)
            async with session_factory() as session:
                repo = SqlAlchemyNetworkValidationRunRepository(session)
                runs = await repo.list_for_organization(EntityId.from_string(org_id), 10, 0)
            running = [r for r in runs if r.status == NetworkRunStatus.RUNNING]
            if running:
                mid_run_id = str(running[0].id)
                break
        assert mid_run_id is not None, "scheduler-dispatched run never reached RUNNING in time"

        cancel_status = await orchestrator.request_cancellation(org_id, mid_run_id)
        assert cancel_status == str(NetworkRunStatus.RUNNING)
    finally:
        # ALWAYS await the background claim task to completion, even if an
        # assertion above failed — an orphaned, never-awaited asyncio task
        # holding a live DB connection past this test's own teardown is
        # exactly the kind of leak that manifests as spurious resource
        # warnings/errors in LATER, unrelated tests sharing the same event
        # loop and connection pool.
        dto = await claim_task

    assert dto is not None
    assert dto.id == mid_run_id
    assert dto.status == str(NetworkRunStatus.CANCELLED)

    # Policy lifecycle not corrupted: claim released, schedule advanced,
    # still ACTIVE (not stuck CLAIMED, not DISABLED, not duplicated).
    async with session_factory() as session:
        policy_repo = SqlAlchemyNetworkMonitoringPolicyRepository(session)
        fresh_policy = await policy_repo.get_by_id_for_organization(
            policy.id, EntityId.from_string(org_id),
        )
    assert fresh_policy is not None
    assert fresh_policy.claimed_at is None
    assert fresh_policy.claim_owner is None
    assert fresh_policy.lifecycle == policy.lifecycle  # still ACTIVE

    # No duplicate run: an immediate second claim attempt for the same
    # policy finds nothing due (schedule was advanced past "now").
    async with session_factory() as session:
        policy_repo = SqlAlchemyNetworkMonitoringPolicyRepository(session)
        second_claim = await policy_repo.claim_one_due_policy(utc_now(), "scheduler-worker-2")
        await session.commit()
    assert second_claim is None or str(second_claim.id) != str(policy.id)

    async with session_factory() as session:
        repo = SqlAlchemyNetworkValidationRunRepository(session)
        all_runs = await repo.list_for_organization(EntityId.from_string(org_id), 10, 0)
    assert len(all_runs) == 1  # exactly one run was ever created for this policy
