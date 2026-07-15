"""Restart durability proof for NetworkValidationRun cancellation — M16
adversarial traceability scenario #51 (final audit requirement).

Simulates a real process restart by constructing THREE fully independent
`redforge.app.create_app()` instances (each with its own `lifespan_context`
enter/exit, its own DB engine, its own dependency-injection wiring) against
the SAME real, persistent PostgreSQL database — the only way state can
survive between them is Postgres itself, exactly as it would across a real
process restart, since this application holds no in-process execution
registry or cache for NetworkValidationRun.

Process A: a run is driven directly to RUNNING (simulating a genuine
in-flight execution) and then abandoned WITHOUT calling finish()/cancel()
— modeling a process crash mid-execution. Process A's engine is disposed.

Process B (a brand-new app/engine — the "restarted" process): queries the
abandoned run over real HTTP, confirms it is still RUNNING with
cancellation_requested=false, then cancels it over real HTTP. Process B's
engine is disposed.

Process C (a second "restart"): queries the SAME run over real HTTP and
proves cancellation_requested is still true and the run has NOT silently
resumed or been re-completed by anything — proving there is no background
resumption of an abandoned execution anywhere in this system. Process C
also proves the scheduler itself is not corrupted by the abandoned run:
a fresh, unrelated ACTIVE policy is still claimable via the real
SKIP LOCKED claim path.
"""

from __future__ import annotations

import asyncio
import gc
import os

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.domain.authorization.entity import SecurityAuthorization
from redforge.domain.authorization.value_objects import (
    ActionClass,
    AuthorizationScopeEntry,
    ScopeEntityType,
    ValidityWindow,
)
from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import AssetDiscoverySource, AssetType
from redforge.domain.network_security.entity import (
    NetworkMonitoringPolicy,
    NetworkValidationRun,
)
from redforge.domain.network_security.value_objects import (
    NetworkValidationProfile,
    ValidationCadence,
)
from redforge.infrastructure.database.repositories.authorization.repository import (
    SqlAlchemySecurityAuthorizationRepository,
)
from redforge.infrastructure.database.repositories.network_security.policy_repository import (
    SqlAlchemyNetworkMonitoringPolicyRepository,
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


def _assert_isolated_proof_database(target_db_name: str) -> None:
    assert target_db_name == _TEST_DB_NAME, (
        f"REFUSING destructive command: target database {target_db_name!r} is not the "
        f"isolated proof database {_TEST_DB_NAME!r}"
    )


async def _register_and_scope(
    client: AsyncClient, email: str, password: str, slug: str,
) -> tuple[str, str]:
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "display_name": "Restart Proof User", "password": password},
    )
    assert r.status_code == 201, r.text
    unscoped_token = r.json()["access_token"]
    r = await client.post(
        "/api/v1/organizations",
        json={"name": "M16 Restart Proof Org", "slug": slug},
        headers={"Authorization": f"Bearer {unscoped_token}"},
    )
    assert r.status_code == 201, r.text
    org_id = r.json()["id"]
    r = await client.post(
        f"/api/v1/auth/organizations/{org_id}/select",
        headers={"Authorization": f"Bearer {unscoped_token}"},
    )
    assert r.status_code == 200, r.text
    return org_id, r.json()["access_token"]


async def _settle_after_simulated_process_exit() -> None:
    """After a `lifespan_context`'s __aexit__ returns, each background
    worker's own stop() has requested cancellation of its poll-loop task,
    but the underlying asyncpg connection/pool teardown those tasks
    triggered is scheduled on the event loop, not necessarily complete
    yet. Give it a couple of loop turns and force GC of anything already
    dereferenced, so any resource warning surfaces deterministically HERE
    (attributable to this exact simulated "process exit") rather than
    nondeterministically during a later, unrelated test's own GC pass."""
    for _ in range(5):
        await asyncio.sleep(0)
    gc.collect()


async def _login_and_scope(client: AsyncClient, email: str, password: str, org_id: str) -> str:
    r = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    unscoped_token = r.json()["access_token"]
    r = await client.post(
        f"/api/v1/auth/organizations/{org_id}/select",
        headers={"Authorization": f"Bearer {unscoped_token}"},
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


async def test_cancellation_request_survives_two_simulated_process_restarts() -> None:
    _assert_isolated_proof_database(_TEST_DB_NAME)

    suffix = str(EntityId.generate()).lower()
    email = f"m16-restart-proof-{suffix}@example.test"
    password = "SecureP@ssRestart123"
    slug = f"m16-restart-proof-org-{suffix}"

    # ─── Process A: register tenant, create+authorize a target, drive a
    # run to RUNNING, then abandon it (no finish()/cancel()) — models a
    # crash mid-execution. Process A's engine is disposed afterward,
    # simulating the process dying. ───────────────────────────────────
    engine_a = create_async_engine(_DB_URL, echo=False)
    factory_a = async_sessionmaker(engine_a, expire_on_commit=False)

    from redforge.app import create_app
    from redforge.core.config import Settings

    settings = Settings(database_url=_DB_URL)
    app_a = create_app(settings=settings)
    async with app_a.router.lifespan_context(app_a):
        transport_a = ASGITransport(app=app_a, raise_app_exceptions=False)
        async with AsyncClient(transport=transport_a, base_url="http://test") as client_a:
            org_id, _ = await _register_and_scope(client_a, email, password, slug)
    await _settle_after_simulated_process_exit()

    asset_service = TenantAssetService(factory_a)
    ip_asset = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.IP_ADDRESS,
        scheme=IdentityScheme.IP_ADDRESS, raw_external_id="203.0.113.50",
        name="203.0.113.50", description="Restart durability proof target",
        discovery_source=AssetDiscoverySource.API_SCAN,
    )

    requester_id = EntityId.generate()
    approver_id = EntityId.generate()
    authorization = SecurityAuthorization.create(
        organization_id=EntityId.from_string(org_id),
        requester_user_id=requester_id,
        validity=ValidityWindow(
            valid_from=utc_now(), valid_until=utc_now().replace(year=utc_now().year + 1),
        ),
        action_classes={ActionClass.ACTIVE_VALIDATION},
        scope={AuthorizationScopeEntry(entity_type=ScopeEntityType.AI_ASSET, entity_id=ip_asset.id)},
    )
    authorization.submit_for_approval()
    authorization.approve(approver_id)
    async with factory_a() as session:
        await SqlAlchemySecurityAuthorizationRepository(session).save(authorization)
        await session.commit()

    run = NetworkValidationRun.create(
        organization_id=EntityId.from_string(org_id),
        target_asset_id=EntityId.from_string(ip_asset.id),
        requester_user_id=requester_id,
        profile=NetworkValidationProfile.NETWORK_DEEP_SAFE,
    )
    run.begin_policy_check()
    run.authorize(authorization.id)
    run.start()  # RUNNING — then abandoned, exactly like a crashed process
    async with factory_a() as session:
        await SqlAlchemyNetworkValidationRunRepository(session).save(run)
        await session.commit()
    run_id = str(run.id)

    await engine_a.dispose()  # "process A" is gone

    # ─── Process B: a brand-new app/engine — the restarted process.
    # Queries the abandoned run over real HTTP; it must still be RUNNING
    # with cancellation_requested=false (nothing resumed or silently
    # finished it while "the process was down"). Then cancels it over
    # real HTTP. ─────────────────────────────────────────────────────
    app_b = create_app(settings=Settings(database_url=_DB_URL))
    async with app_b.router.lifespan_context(app_b):
        transport_b = ASGITransport(app=app_b, raise_app_exceptions=False)
        async with AsyncClient(transport=transport_b, base_url="http://test") as client_b:
            scoped_token_b = await _login_and_scope(client_b, email, password, org_id)
            headers_b = {"Authorization": f"Bearer {scoped_token_b}"}

            r = await client_b.get(f"/api/v1/network-security/runs/{run_id}", headers=headers_b)
            assert r.status_code == 200, r.text
            assert r.json()["status"] == "running"
            assert r.json()["cancellation_requested"] is False

            r = await client_b.post(
                f"/api/v1/network-security/runs/{run_id}/cancel", headers=headers_b,
            )
            assert r.status_code == 200, r.text
            assert r.json()["cancellation_requested"] is True
            # Cancellation is REQUESTED, not itself a lifecycle transition —
            # only the (now-dead) orchestrator coroutine would have made the
            # RUNNING -> CANCELLED transition. This is the exact scenario
            # scenario #51 requires: the flag must be observable and durable
            # independent of whether the original execution is still alive.
            assert r.json()["status"] == "running"

    # process_b's engine (owned by the app's own DI wiring) is disposed
    # when its lifespan_context exits above.
    await _settle_after_simulated_process_exit()

    # ─── Process C: a second simulated restart. Proves the cancellation
    # request survived across BOTH restarts, the run has not silently
    # resumed/re-completed (no background resumption of an abandoned
    # execution exists anywhere in this system), and the scheduler
    # itself is unaffected by the abandoned run. ────────────────────────
    engine_c = create_async_engine(_DB_URL, echo=False)
    factory_c = async_sessionmaker(engine_c, expire_on_commit=False)

    app_c = create_app(settings=Settings(database_url=_DB_URL))
    async with app_c.router.lifespan_context(app_c):
        transport_c = ASGITransport(app=app_c, raise_app_exceptions=False)
        async with AsyncClient(transport=transport_c, base_url="http://test") as client_c:
            scoped_token_c = await _login_and_scope(client_c, email, password, org_id)
            headers_c = {"Authorization": f"Bearer {scoped_token_c}"}

            r = await client_c.get(f"/api/v1/network-security/runs/{run_id}", headers=headers_c)
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["cancellation_requested"] is True, (
                "cancellation_requested did not survive two simulated process restarts"
            )
            assert body["status"] == "running", (
                "the abandoned run silently resumed/completed instead of remaining exactly "
                "where the crashed process left it — no code path in this system may advance "
                "this run's lifecycle except the (now-dead) orchestrator coroutine that "
                "originally called start()"
            )
    await _settle_after_simulated_process_exit()

    # Remove stale network_monitoring_policies (and their FK dependents) left
    # by previous runs of this test in the isolated proof database.
    #
    # claim_one_due_policy selects globally by next_due_at ASC; without this
    # cleanup a policy row from a prior run whose lease has expired
    # (> CLAIM_LEASE_SECONDS) is claimed instead of the fresh policy created
    # just below, making the assertion observe a wrong id.
    #
    # Deletion is scoped to organization_id != org_id so the current test's
    # own RUNNING validation run (org_id) is never touched.  FK dependency
    # order: children must be deleted before their parents.
    async with factory_c() as session:
        # Validate the ACTUAL connected database identity before any DELETE.
        # _assert_isolated_proof_database(_TEST_DB_NAME) is a tautological
        # string guard only; this query proves the live connection resolves to
        # the approved proof database, catching REDFORGE_TEST_DATABASE_URL
        # overrides that would otherwise redirect destructive cleanup to a
        # non-test database.
        _result = await session.execute(text("SELECT current_database()"))
        _actual_db = _result.scalar_one()
        assert _actual_db == _TEST_DB_NAME, (
            f"REFUSING destructive cleanup: connected database is {_actual_db!r}, "
            f"not the approved proof database {_TEST_DB_NAME!r}"
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
            await session.execute(
                text(f"DELETE FROM {_tbl} WHERE organization_id != :oid"),
                {"oid": org_id},
            )
        await session.commit()

    # Scheduler not corrupted by the abandoned run: an unrelated fresh
    # ACTIVE policy is still claimable via the real SKIP LOCKED path.
    other_asset = await TenantAssetService(factory_c).resolve_asset(
        organization_id=org_id, asset_type=AssetType.IP_ADDRESS,
        scheme=IdentityScheme.IP_ADDRESS, raw_external_id="203.0.113.51",
        name="203.0.113.51", description="Post-restart scheduler-health target",
        discovery_source=AssetDiscoverySource.API_SCAN,
    )
    policy = NetworkMonitoringPolicy.create(
        organization_id=EntityId.from_string(org_id),
        target_asset_id=EntityId.from_string(other_asset.id),
        requester_user_id=requester_id, profile=NetworkValidationProfile.NETWORK_BASELINE,
        cadence=ValidationCadence.HOURLY,
    )
    policy.activate(utc_now())
    async with factory_c() as session:
        await SqlAlchemyNetworkMonitoringPolicyRepository(session).save(policy)
        await session.commit()
    async with factory_c() as session:
        claimed = await SqlAlchemyNetworkMonitoringPolicyRepository(session).claim_one_due_policy(
            utc_now(), "post-restart-worker",
        )
        await session.commit()
    assert claimed is not None and str(claimed.id) == str(policy.id), (
        "scheduler claim path is corrupted or blocked by the abandoned RUNNING run"
    )

    await engine_c.dispose()
