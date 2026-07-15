"""Real PostgreSQL concurrency proof for M16 — NetworkMonitoringPolicy
scheduler claim safety.

Runs against the dedicated, migrated `redforge_test` database (the same
DB application/network_security's other integration tests already use
in this session). Proves the SKIP LOCKED claim idiom
(SqlAlchemyNetworkMonitoringPolicyRepository.claim_one_due_policy)
converges on exactly ONE winner under genuine concurrent contention —
mirroring M14's own concurrent-claim proof precedent.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import AssetDiscoverySource, AssetType
from redforge.domain.network_security.entity import NetworkMonitoringPolicy
from redforge.domain.network_security.value_objects import (
    NetworkValidationProfile,
    ValidationCadence,
)
from redforge.infrastructure.database.repositories.network_security.policy_repository import (
    SqlAlchemyNetworkMonitoringPolicyRepository,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

pytestmark = pytest.mark.asyncio

_TEST_DB_NAME = "redforge_test"
_DB_URL = f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_TEST_DB_NAME}"


@pytest.fixture
async def session_factory():
    engine = create_async_engine(_DB_URL, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.fixture(autouse=True)
async def _clean_policies(session_factory):
    """Delete all network_monitoring_policy rows (and FK dependents) before
    each test.

    This file asserts global scheduler claim behaviour (SKIP LOCKED across the
    whole table).  Without this cleanup, active due rows left by previous test
    runs accumulate in redforge_test and either steal the claim from the
    test-owned policy (causing the exactly-one-winner assertion to see 0
    winners) or cause the paused/disabled tests to get a non-None result.

    FK dependency order must be respected so no constraint is violated:
    children are deleted before parents.
    """
    async with session_factory() as session:
        # Validate the ACTUAL connected database identity before any DELETE.
        # This catches environment-variable or config mistakes that would
        # otherwise run destructive cleanup against a non-test database.
        _result = await session.execute(text("SELECT current_database()"))
        _actual_db = _result.scalar_one()
        assert _actual_db == _TEST_DB_NAME, (
            f"REFUSING destructive cleanup: connected database is {_actual_db!r}, "
            f"not the approved integration-test database {_TEST_DB_NAME!r}"
        )
        for _tbl in (
            "network_validation_run_events",
            "network_state_snapshots",
            "network_drift_events",
            "network_observations",
            "network_monitoring_policy_lifecycle_events",
            "network_validation_runs",
            "network_monitoring_policies",
        ):
            await session.execute(text(f"DELETE FROM {_tbl}"))
        await session.commit()
    yield


async def _create_target_asset(session_factory, organization_id: str, ip: str) -> EntityId:
    asset_service = TenantAssetService(session_factory)
    asset = await asset_service.resolve_asset(
        organization_id=organization_id, asset_type=AssetType.IP_ADDRESS,
        scheme=IdentityScheme.IP_ADDRESS, raw_external_id=ip, name=ip,
        description="concurrency proof target", discovery_source=AssetDiscoverySource.API_SCAN,
    )
    return EntityId.from_string(asset.id)


async def test_concurrent_scheduler_claim_converges_on_exactly_one_winner(
    session_factory,
) -> None:
    org_id = EntityId.generate()
    target_asset_id = await _create_target_asset(session_factory, str(org_id), "203.0.113.100")
    requester_id = EntityId.generate()

    policy = NetworkMonitoringPolicy.create(
        organization_id=org_id, target_asset_id=target_asset_id,
        requester_user_id=requester_id, profile=NetworkValidationProfile.NETWORK_BASELINE,
        cadence=ValidationCadence.HOURLY,
    )
    policy.activate(utc_now())

    async with session_factory() as session:
        repo = SqlAlchemyNetworkMonitoringPolicyRepository(session)
        await repo.save(policy)
        await session.commit()

    async def _claim_attempt(worker_id: str) -> NetworkMonitoringPolicy | None:
        async with session_factory() as session:
            repo = SqlAlchemyNetworkMonitoringPolicyRepository(session)
            claimed = await repo.claim_one_due_policy(utc_now(), worker_id)
            await session.commit()
            return claimed

    results = await asyncio.gather(
        *(_claim_attempt(f"worker-{i}") for i in range(20))
    )
    # `claim_one_due_policy()` claims ANY due ACTIVE policy in the whole
    # table (a genuine, correct global scheduler scan — see its own
    # docstring), so this proof DB may legitimately contain OTHER due
    # policies left over from other tests in the same session. The
    # claim-safety property under test is per-policy, not "exactly one
    # claim across the entire table" — so this asserts THIS policy was
    # claimed by at most one of the 20 concurrent attempts, never two.
    winners_of_this_policy = [
        r for r in results if r is not None and str(r.id) == str(policy.id)
    ]
    assert len(winners_of_this_policy) == 1


async def test_paused_policy_never_claimed(session_factory) -> None:
    org_id = EntityId.generate()
    target_asset_id = await _create_target_asset(session_factory, str(org_id), "203.0.113.101")
    requester_id = EntityId.generate()

    policy = NetworkMonitoringPolicy.create(
        organization_id=org_id, target_asset_id=target_asset_id,
        requester_user_id=requester_id, profile=NetworkValidationProfile.NETWORK_BASELINE,
        cadence=ValidationCadence.HOURLY,
    )
    policy.activate(utc_now())
    policy.pause(utc_now())

    async with session_factory() as session:
        repo = SqlAlchemyNetworkMonitoringPolicyRepository(session)
        await repo.save(policy)
        await session.commit()

    async with session_factory() as session:
        repo = SqlAlchemyNetworkMonitoringPolicyRepository(session)
        claimed = await repo.claim_one_due_policy(utc_now(), "worker-x")
        await session.commit()
    assert claimed is None


async def test_disabled_policy_never_claimed(session_factory) -> None:
    org_id = EntityId.generate()
    target_asset_id = await _create_target_asset(session_factory, str(org_id), "203.0.113.102")
    requester_id = EntityId.generate()

    policy = NetworkMonitoringPolicy.create(
        organization_id=org_id, target_asset_id=target_asset_id,
        requester_user_id=requester_id, profile=NetworkValidationProfile.NETWORK_BASELINE,
        cadence=ValidationCadence.HOURLY,
    )
    policy.activate(utc_now())
    policy.disable(utc_now())

    async with session_factory() as session:
        repo = SqlAlchemyNetworkMonitoringPolicyRepository(session)
        await repo.save(policy)
        await session.commit()

    async with session_factory() as session:
        repo = SqlAlchemyNetworkMonitoringPolicyRepository(session)
        claimed = await repo.claim_one_due_policy(utc_now(), "worker-x")
        await session.commit()
    assert claimed is None
