"""M22 Phase 2 — Feed Synchronization Foundation: PostgreSQL
integration, migration verification, and HTTP acceptance proof suite.

Runs against a DEDICATED proof database
(`redforge_m22_feed_sync_proof_test` by default), migrated to head via
`alembic upgrade head` before this file runs — never against the
shared dev `redforge` database, and never against the M22 Phase 1
proof database either (Phase 2 owns its own dedicated proof DB, per
the `feeds`/`feed_sync_runs` tables introduced by migration 0036).
Every assertion here uses real PostgreSQL; no mocks on repositories,
the database, or the migration itself.

Covers:
  Section A: Migration verification — schema shape matches the
             approved design (scope/org CHECK constraint, two partial
             unique indexes on `feeds.feed_key`, the partial unique
             active-run index on `feed_sync_runs`, the cascading FK,
             migration head is 0036).
  Section B: Repository-level proof — `Feed`/`FeedSyncRun` add/update/
             get/find_by_key/list_all/list_due_for_sync, duplicate-key
             conflict mapping, and the DB-level active-run uniqueness
             backstop.
  Section C: Application-service proof — registration, lifecycle
             transitions, configuration updates, and platform audit
             logging (`FeedAdminService`, `FeedQueryService`).
  Section D: Orchestration-service proof — end-to-end synchronization
             lifecycle (success and permanent-failure paths) through a
             deliberately generic, test-only stub `FeedSyncExecutor`
             (never a real STIX/TAXII connector — Phase 2 explicitly
             does not implement one), retry/backoff attempt counting,
             per-feed advisory-lock concurrency safety, and the
             `UnknownFeedConnectorError` honest-failure path for every
             `FeedSourceKind` with no registered connector.
  Section E: HTTP acceptance — real JWT via the platform bootstrap
             flow, PlatformPermission enforcement (401/403/2xx) on the
             internal administration API, and an end-to-end register
             -> activate -> trigger-sync -> list-runs round trip.
"""

from __future__ import annotations

import asyncio
import os
import time

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.threat_intel.feed_admin_service import FeedAdminService
from redforge.application.threat_intel.feed_connector import (
    FeedConnectorRegistry,
    FeedSyncContext,
    FeedSyncOutcome,
)
from redforge.application.threat_intel.feed_query_service import FeedQueryService
from redforge.application.threat_intel.feed_sync_orchestration_service import (
    FeedSyncOrchestrationService,
)
from redforge.domain.threat_intel.feed_entity import Feed
from redforge.domain.threat_intel.feed_exceptions import (
    DuplicateFeedKeyError,
    FeedNotActiveError,
    FeedSyncAlreadyRunningError,
    UnknownFeedConnectorError,
)
from redforge.domain.threat_intel.feed_sync_run_entity import FeedSyncRun
from redforge.domain.threat_intel.feed_value_objects import (
    FeedKey,
    FeedSourceKind,
    FeedStatus,
    FeedSyncRunStatus,
    FeedSyncTrigger,
    RetryPolicy,
    SyncSchedule,
)
from redforge.domain.threat_intel.reference_data_value_objects import IngestionScope
from redforge.infrastructure.audit.contracts import AuditAction
from redforge.infrastructure.audit.platform_audit_log import PostgresPlatformAuditLog
from redforge.infrastructure.database.repositories.feed_sync_repository import (
    SqlAlchemyFeedRepository,
    SqlAlchemyFeedSyncRunRepository,
)
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio(loop_scope="module")

_DB_NAME = "redforge_m22_feed_sync_proof_test"
_DB_URL = os.environ.get(
    "REDFORGE_M22_FEED_SYNC_TEST_DATABASE_URL",
    f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_DB_NAME}",
)

# A fast, deterministic RetryPolicy for tests — zero delay so the
# executor's own retry/backoff behavior is exercised without the test
# suite actually sleeping.
_FAST_RETRY = RetryPolicy(
    max_attempts=3, base_delay_seconds=0.0, max_delay_seconds=0.0, jitter_factor=0.0
)


def _unique_key(prefix: str) -> str:
    return f"{prefix}_{time.time_ns()}"


# ─── Test-only stub connector (never a real STIX/TAXII implementation) ──────


class _StubExecutor:
    """Deliberately generic test double for `FeedSyncExecutor` — proves
    the connector seam (`FeedConnectorRegistry` + orchestration
    service) works end to end without implementing any real feed
    provider, which M22 Phase 2 explicitly excludes."""

    def __init__(
        self,
        *,
        fail_times: int = 0,
        checkpoint: str = "cursor-1",
        error_message: str = "stub connector failure",
    ) -> None:
        self.fail_times = fail_times
        self.checkpoint = checkpoint
        self.error_message = error_message
        self.call_count = 0
        self.contexts: list[FeedSyncContext] = []

    async def execute(self, context: FeedSyncContext) -> FeedSyncOutcome:
        self.contexts.append(context)
        self.call_count += 1
        if self.call_count <= self.fail_times:
            raise RuntimeError(self.error_message)
        return FeedSyncOutcome(
            checkpoint=self.checkpoint, items_fetched=5, items_processed=5, items_failed=0
        )


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def session_factory():
    engine = create_async_engine(_DB_URL, echo=False)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client():
    """Full production app against the M22 Phase 2 proof database.
    Startup runs the REAL startup validator (migration-head check
    included) — this fixture failing to construct is itself proof the
    startup validator accepts a database migrated to 0036."""
    from unittest.mock import patch

    from redforge.app import create_app
    from redforge.core.config import Settings
    from redforge.infrastructure.rate_limiting.contracts import RateLimitResult
    from redforge.infrastructure.rate_limiting.sliding_window import (
        InMemorySlidingWindowLimiter,
    )

    async def _always_allow(
        self: object, key: str, max_requests: int, window_seconds: int,
    ) -> RateLimitResult:
        return RateLimitResult(
            allowed=True, remaining=max_requests, limit=max_requests, retry_after_seconds=0,
        )

    bootstrap_env = {
        "REDFORGE_PLATFORM_BOOTSTRAP_ENABLED": "true",
        "REDFORGE_PLATFORM_BOOTSTRAP_PRINCIPAL_EMAIL": "m22p2-super-admin@redforge.test",
    }
    previous_env = {k: os.environ.get(k) for k in bootstrap_env}
    os.environ.update(bootstrap_env)
    try:
        with patch.object(InMemorySlidingWindowLimiter, "check", _always_allow):
            app = create_app(
                settings=Settings(
                    database_url=_DB_URL,
                    platform_bootstrap_enabled=True,
                    platform_bootstrap_principal_email="m22p2-super-admin@redforge.test",
                )
            )
            async with app.router.lifespan_context(app):
                transport = ASGITransport(app=app, raise_app_exceptions=False)
                async with AsyncClient(transport=transport, base_url="http://test") as c:
                    yield c
    finally:
        for key, value in previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


async def _register(client: AsyncClient, email: str) -> str:
    password = "SecureP@ss123"
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "display_name": "M22P2 Test User", "password": password},
    )
    if r.status_code == 201:
        return r.json()["access_token"]
    if r.status_code == 409:
        r = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200, r.text
        return r.json()["access_token"]
    raise AssertionError(f"Register failed: {r.status_code} {r.text}")


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def super_admin_token(client: AsyncClient) -> str:
    token = await _register(client, "m22p2-super-admin@redforge.test")
    r = await client.post(
        "/api/v1/platform/bootstrap", headers={"Authorization": f"Bearer {token}"}
    )
    if r.status_code == 201:
        assert r.json()["role"] == "platform_super_admin"
    else:
        assert r.status_code == 409, r.text
    return token


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def no_platform_role_token(client: AsyncClient) -> str:
    return await _register(client, _unique_key("no-role") + "@redforge.test")


# ─────────────────────────────────────────────────────────────────────────────
# Section A — Migration verification
# ─────────────────────────────────────────────────────────────────────────────


class TestMigrationSchema:
    async def test_migration_head_is_0036(self, session_factory) -> None:
        async with session_factory() as session:
            result = await session.execute(text("SELECT version_num FROM alembic_version"))
            assert result.scalar_one() == "0039"

    async def test_feeds_scope_org_pairing_check_constraint_exists(self, session_factory) -> None:
        async with session_factory() as session:
            result = await session.execute(
                text(
                    "SELECT conname FROM pg_constraint "
                    "WHERE conname = 'ck_feeds_ck_feeds_scope_org_pairing'"
                )
            )
            assert result.first() is not None

    async def test_feeds_has_two_partial_unique_key_indexes(self, session_factory) -> None:
        async with session_factory() as session:
            result = await session.execute(
                text(
                    "SELECT indexname FROM pg_indexes WHERE tablename = 'feeds' "
                    "AND indexname IN ('ux_feeds_global_key', 'ux_feeds_tenant_org_key')"
                )
            )
            names = {row[0] for row in result.all()}
            assert names == {"ux_feeds_global_key", "ux_feeds_tenant_org_key"}

    async def test_feed_sync_runs_has_partial_unique_active_run_index(
        self, session_factory
    ) -> None:
        async with session_factory() as session:
            result = await session.execute(
                text(
                    "SELECT indexdef FROM pg_indexes "
                    "WHERE tablename = 'feed_sync_runs' AND indexname = 'ux_fsr_feed_active_run'"
                )
            )
            row = result.first()
            assert row is not None
            assert "pending" in row[0] and "running" in row[0]

    async def test_feed_sync_runs_fk_cascades_on_feed_delete(self, session_factory) -> None:
        async with session_factory() as session:
            result = await session.execute(
                text(
                    "SELECT confdeltype FROM pg_constraint WHERE conname = 'fk_fsr_feed'"
                )
            )
            row = result.first()
            assert row is not None
            assert row[0] == b"c"  # 'c' = CASCADE (asyncpg decodes pg "char" as bytes)

    async def test_feeds_carries_no_deferrable_fk_since_no_self_reference(
        self, session_factory
    ) -> None:
        """Sanity check distinguishing this migration's design from
        0035's self-referencing ATT&CK technique FK: `feeds` has no
        self-referencing column at all."""
        async with session_factory() as session:
            result = await session.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = 'feeds' AND column_name = 'parent_technique_id'"
                )
            )
            assert result.first() is None


# ─────────────────────────────────────────────────────────────────────────────
# Section B — Repository proof
# ─────────────────────────────────────────────────────────────────────────────


class TestFeedRepository:
    async def test_add_then_get_by_id_and_find_by_key(self, session_factory) -> None:
        feed_key = _unique_key("repo_feed")
        async with session_factory() as session:
            repo = SqlAlchemyFeedRepository(session)
            feed = Feed.register(
                id=str(EntityId.generate()),
                feed_key=FeedKey(feed_key),
                display_name="Repo Test Feed",
                source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD,
                schedule=SyncSchedule(interval_seconds=600),
                actor_id="tester",
            )
            added = await repo.add(feed)
            await session.commit()
            assert added.feed_key.value == feed_key

            fetched = await repo.get_by_id(added.id)
            assert fetched is not None
            assert fetched.display_name == "Repo Test Feed"

            found = await repo.find_by_key(feed_key, scope=IngestionScope.GLOBAL)
            assert found is not None
            assert found.id == added.id

    async def test_duplicate_global_feed_key_raises_conflict(self, session_factory) -> None:
        feed_key = _unique_key("dup_feed")
        async with session_factory() as session:
            repo = SqlAlchemyFeedRepository(session)
            first = Feed.register(
                id=str(EntityId.generate()),
                feed_key=FeedKey(feed_key),
                display_name="First",
                source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD,
                schedule=SyncSchedule(interval_seconds=600),
                actor_id="tester",
            )
            await repo.add(first)
            await session.commit()

        async with session_factory() as session:
            repo = SqlAlchemyFeedRepository(session)
            second = Feed.register(
                id=str(EntityId.generate()),
                feed_key=FeedKey(feed_key),
                display_name="Second",
                source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD,
                schedule=SyncSchedule(interval_seconds=600),
                actor_id="tester",
            )
            with pytest.raises(DuplicateFeedKeyError):
                await repo.add(second)
            await session.rollback()

    async def test_global_and_tenant_scope_do_not_collide_on_same_feed_key(
        self, session_factory
    ) -> None:
        feed_key = _unique_key("scope_collision_feed")
        async with session_factory() as session:
            repo = SqlAlchemyFeedRepository(session)
            global_feed = Feed.register(
                id=str(EntityId.generate()),
                feed_key=FeedKey(feed_key),
                display_name="Global Variant",
                source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD,
                schedule=SyncSchedule(interval_seconds=600),
                actor_id="tester",
                scope=IngestionScope.GLOBAL,
            )
            await repo.add(global_feed)
            await session.commit()

            tenant_feed = Feed.register(
                id=str(EntityId.generate()),
                feed_key=FeedKey(feed_key),
                display_name="Tenant Variant",
                source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD,
                schedule=SyncSchedule(interval_seconds=600),
                actor_id="tester",
                scope=IngestionScope.TENANT,
                organization_id="org-proof-1",
            )
            await repo.add(tenant_feed)
            await session.commit()

            g_found = await repo.find_by_key(feed_key, scope=IngestionScope.GLOBAL)
            t_found = await repo.find_by_key(
                feed_key, scope=IngestionScope.TENANT, organization_id="org-proof-1"
            )
            assert g_found is not None and g_found.organization_id is None
            assert t_found is not None and t_found.organization_id == "org-proof-1"

    async def test_scope_org_pairing_violation_rejected_at_db_level(
        self, session_factory
    ) -> None:
        async with session_factory() as session:
            with pytest.raises(IntegrityError):
                await session.execute(
                    text(
                        "INSERT INTO feeds (id, feed_key, display_name, source_kind, scope, "
                        "organization_id, status, connector_config, schedule_interval_seconds, "
                        "created_at, updated_at, created_by, updated_by) VALUES "
                        "(:id, :key, 'Bad', 'static_http_download', 'GLOBAL', "
                        "'org-should-fail', 'draft', '{}', 600, now(), now(), 'x', 'x')"
                    ),
                    {"id": str(EntityId.generate()), "key": _unique_key("bad_scope")},
                )
            await session.rollback()

    async def test_update_persists_lifecycle_and_configuration_changes(
        self, session_factory
    ) -> None:
        async with session_factory() as session:
            repo = SqlAlchemyFeedRepository(session)
            feed = Feed.register(
                id=str(EntityId.generate()),
                feed_key=FeedKey(_unique_key("update_feed")),
                display_name="Before Update",
                source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD,
                schedule=SyncSchedule(interval_seconds=600),
                actor_id="tester",
            )
            feed = await repo.add(feed)
            await session.commit()

            feed.activate(actor_id="tester")
            feed.update_configuration(actor_id="tester", display_name="After Update")
            await repo.update(feed)
            await session.commit()

            fetched = await repo.get_by_id(feed.id)
            assert fetched is not None
            assert fetched.status is FeedStatus.ACTIVE
            assert fetched.display_name == "After Update"

    async def test_list_due_for_sync_returns_only_active_and_overdue_feeds(
        self, session_factory
    ) -> None:
        from datetime import UTC, datetime, timedelta

        async with session_factory() as session:
            repo = SqlAlchemyFeedRepository(session)

            due_feed = Feed.register(
                id=str(EntityId.generate()),
                feed_key=FeedKey(_unique_key("due_feed")),
                display_name="Due Feed",
                source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD,
                schedule=SyncSchedule(interval_seconds=600),
                actor_id="tester",
            )
            due_feed = await repo.add(due_feed)
            due_feed.activate(actor_id="tester", now=datetime.now(UTC) - timedelta(hours=1))
            await repo.update(due_feed)

            not_due_feed = Feed.register(
                id=str(EntityId.generate()),
                feed_key=FeedKey(_unique_key("not_due_feed")),
                display_name="Not Due Feed",
                source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD,
                schedule=SyncSchedule(interval_seconds=600),
                actor_id="tester",
            )
            not_due_feed = await repo.add(not_due_feed)
            not_due_feed.activate(actor_id="tester")
            # record a successful sync just now, pushing next_sync_due_at
            # 600s into the future — must NOT show up as due.
            not_due_feed.record_sync_succeeded(checkpoint=None)
            await repo.update(not_due_feed)

            draft_feed = Feed.register(
                id=str(EntityId.generate()),
                feed_key=FeedKey(_unique_key("draft_feed")),
                display_name="Draft Feed",
                source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD,
                schedule=SyncSchedule(interval_seconds=600),
                actor_id="tester",
            )
            await repo.add(draft_feed)
            await session.commit()

            due = await repo.list_due_for_sync(now=datetime.now(UTC), limit=100)
            due_ids = {f.id for f in due}
            assert due_feed.id in due_ids
            assert not_due_feed.id not in due_ids
            assert draft_feed.id not in due_ids


class TestFeedSyncRunRepository:
    async def test_add_enforces_single_active_run_per_feed(self, session_factory) -> None:
        async with session_factory() as session:
            feed_repo = SqlAlchemyFeedRepository(session)
            feed = Feed.register(
                id=str(EntityId.generate()),
                feed_key=FeedKey(_unique_key("run_conflict_feed")),
                display_name="Run Conflict Feed",
                source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD,
                schedule=SyncSchedule(interval_seconds=600),
                actor_id="tester",
            )
            feed = await feed_repo.add(feed)
            await session.commit()

        async with session_factory() as session:
            run_repo = SqlAlchemyFeedSyncRunRepository(session)
            first_run = FeedSyncRun.start(
                id=str(EntityId.generate()),
                feed_id=feed.id,
                trigger=FeedSyncTrigger.MANUAL,
                checkpoint_before=None,
                created_by="tester",
            )
            await run_repo.add(first_run)
            await session.commit()

        async with session_factory() as session:
            run_repo = SqlAlchemyFeedSyncRunRepository(session)
            second_run = FeedSyncRun.start(
                id=str(EntityId.generate()),
                feed_id=feed.id,
                trigger=FeedSyncTrigger.MANUAL,
                checkpoint_before=None,
                created_by="tester",
            )
            with pytest.raises(FeedSyncAlreadyRunningError):
                await run_repo.add(second_run)
            await session.rollback()

        async with session_factory() as session:
            run_repo = SqlAlchemyFeedSyncRunRepository(session)
            active = await run_repo.get_active_run_for_feed(feed.id)
            assert active is not None
            assert active.id == first_run.id

    async def test_finalized_run_allows_a_new_run_to_start(self, session_factory) -> None:
        async with session_factory() as session:
            feed_repo = SqlAlchemyFeedRepository(session)
            feed = Feed.register(
                id=str(EntityId.generate()),
                feed_key=FeedKey(_unique_key("run_sequence_feed")),
                display_name="Run Sequence Feed",
                source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD,
                schedule=SyncSchedule(interval_seconds=600),
                actor_id="tester",
            )
            feed = await feed_repo.add(feed)
            await session.commit()

        async with session_factory() as session:
            run_repo = SqlAlchemyFeedSyncRunRepository(session)
            run1 = FeedSyncRun.start(
                id=str(EntityId.generate()),
                feed_id=feed.id,
                trigger=FeedSyncTrigger.MANUAL,
                checkpoint_before=None,
                created_by="tester",
            )
            run1 = await run_repo.add(run1)
            run1.mark_succeeded(
                checkpoint_after="cursor-a",
                items_fetched=1,
                items_processed=1,
                items_failed=0,
                retry_attempts_used=1,
            )
            await run_repo.update(run1)
            await session.commit()

        async with session_factory() as session:
            run_repo = SqlAlchemyFeedSyncRunRepository(session)
            run2 = FeedSyncRun.start(
                id=str(EntityId.generate()),
                feed_id=feed.id,
                trigger=FeedSyncTrigger.SCHEDULED,
                checkpoint_before="cursor-a",
                created_by="system",
            )
            await run_repo.add(run2)
            await session.commit()

            runs = await run_repo.list_by_feed(feed.id)
            assert len(runs) == 2
            count = await run_repo.count_by_feed(feed.id)
            assert count == 2


# ─────────────────────────────────────────────────────────────────────────────
# Section C — Application service proof
# ─────────────────────────────────────────────────────────────────────────────


class TestFeedAdminService:
    async def test_register_activate_pause_disable_lifecycle(self, session_factory) -> None:
        service = FeedAdminService(session_factory)
        feed_key = _unique_key("lifecycle_feed")
        feed = await service.register_feed(
            actor_id="admin-1",
            feed_key=feed_key,
            display_name="Lifecycle Feed",
            source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD.value,
            interval_seconds=600,
        )
        assert feed.status is FeedStatus.DRAFT

        feed = await service.activate_feed(actor_id="admin-1", feed_id=feed.id)
        assert feed.status is FeedStatus.ACTIVE

        feed = await service.pause_feed(actor_id="admin-1", feed_id=feed.id)
        assert feed.status is FeedStatus.PAUSED

        feed = await service.disable_feed(actor_id="admin-1", feed_id=feed.id)
        assert feed.status is FeedStatus.DISABLED

        async with session_factory() as session:
            entries = await PostgresPlatformAuditLog(session).query(
                actor_id="admin-1", action=AuditAction.FEED_REGISTERED, limit=10
            )
            assert any(e.resource_id == feed.id for e in entries)
            disabled_entries = await PostgresPlatformAuditLog(session).query(
                actor_id="admin-1", action=AuditAction.FEED_DISABLED, limit=10
            )
            assert any(e.resource_id == feed.id for e in disabled_entries)

    async def test_update_configuration_changes_schedule_and_retry_policy(
        self, session_factory
    ) -> None:
        service = FeedAdminService(session_factory)
        feed = await service.register_feed(
            actor_id="admin-1",
            feed_key=_unique_key("config_feed"),
            display_name="Config Feed",
            source_kind=FeedSourceKind.HTTP_API_INCREMENTAL.value,
            interval_seconds=600,
        )
        updated = await service.update_configuration(
            actor_id="admin-1",
            feed_id=feed.id,
            interval_seconds=3600,
            retry_policy=RetryPolicy(max_attempts=7),
        )
        assert updated.schedule.interval_seconds == 3600
        assert updated.retry_policy.max_attempts == 7

    async def test_register_duplicate_feed_key_raises(self, session_factory) -> None:
        service = FeedAdminService(session_factory)
        feed_key = _unique_key("dup_svc_feed")
        await service.register_feed(
            actor_id="admin-1",
            feed_key=feed_key,
            display_name="First",
            source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD.value,
            interval_seconds=600,
        )
        with pytest.raises(DuplicateFeedKeyError):
            await service.register_feed(
                actor_id="admin-1",
                feed_key=feed_key,
                display_name="Second",
                source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD.value,
                interval_seconds=600,
            )


class TestFeedQueryService:
    async def test_list_feeds_filters_by_status(self, session_factory) -> None:
        admin = FeedAdminService(session_factory)
        query = FeedQueryService(session_factory)
        feed = await admin.register_feed(
            actor_id="admin-1",
            feed_key=_unique_key("query_feed"),
            display_name="Query Feed",
            source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD.value,
            interval_seconds=600,
        )
        await admin.activate_feed(actor_id="admin-1", feed_id=feed.id)

        active_feeds, total = await query.list_feeds(status=FeedStatus.ACTIVE)
        assert any(f.id == feed.id for f in active_feeds)
        assert total >= 1

        fetched = await query.get_feed(feed.id)
        assert fetched.id == feed.id

    async def test_get_unknown_feed_raises_not_found(self, session_factory) -> None:
        from redforge.core.exceptions import NotFoundError

        query = FeedQueryService(session_factory)
        with pytest.raises(NotFoundError):
            await query.get_feed("does-not-exist")


# ─────────────────────────────────────────────────────────────────────────────
# Section D — Orchestration service proof
# ─────────────────────────────────────────────────────────────────────────────


async def _registered_active_feed(
    session_factory, *, retry_policy: RetryPolicy | None = None
) -> Feed:
    admin = FeedAdminService(session_factory)
    feed = await admin.register_feed(
        actor_id="admin-1",
        feed_key=_unique_key("orch_feed"),
        display_name="Orchestration Feed",
        source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD.value,
        interval_seconds=600,
        retry_policy=retry_policy or _FAST_RETRY,
    )
    return await admin.activate_feed(actor_id="admin-1", feed_id=feed.id)


class TestFeedSyncOrchestrationService:
    async def test_unknown_connector_raises_before_creating_a_run(self, session_factory) -> None:
        feed = await _registered_active_feed(session_factory)
        empty_registry = FeedConnectorRegistry()
        service = FeedSyncOrchestrationService(session_factory, empty_registry)

        with pytest.raises(UnknownFeedConnectorError):
            await service.trigger_sync(
                feed_id=feed.id, trigger=FeedSyncTrigger.MANUAL, actor_id="admin-1"
            )

        query = FeedQueryService(session_factory)
        _runs, total = await query.list_sync_runs(feed.id)
        assert total == 0, "no FeedSyncRun row should exist for an unregistered connector"

    async def test_successful_sync_advances_checkpoint_and_schedule(
        self, session_factory
    ) -> None:
        feed = await _registered_active_feed(session_factory)
        registry = FeedConnectorRegistry()
        stub = _StubExecutor(checkpoint="cursor-success")
        registry.register(FeedSourceKind.STATIC_HTTP_DOWNLOAD, stub)
        service = FeedSyncOrchestrationService(session_factory, registry)

        run = await service.trigger_sync(
            feed_id=feed.id, trigger=FeedSyncTrigger.MANUAL, actor_id="admin-1"
        )
        assert run.status is FeedSyncRunStatus.SUCCEEDED
        assert run.checkpoint_after == "cursor-success"
        assert run.retry_attempts_used == 1
        assert stub.call_count == 1
        assert stub.contexts[0].checkpoint is None  # first-ever sync, no prior checkpoint

        query = FeedQueryService(session_factory)
        updated_feed = await query.get_feed(feed.id)
        assert updated_feed.checkpoint == "cursor-success"
        assert updated_feed.consecutive_failure_count == 0
        assert updated_feed.next_sync_due_at is not None

    async def test_transient_failures_are_retried_then_succeed(self, session_factory) -> None:
        feed = await _registered_active_feed(
            session_factory,
            retry_policy=RetryPolicy(
                max_attempts=3, base_delay_seconds=0.0, max_delay_seconds=0.0, jitter_factor=0.0
            ),
        )
        registry = FeedConnectorRegistry()
        stub = _StubExecutor(fail_times=2, checkpoint="cursor-retried")
        registry.register(FeedSourceKind.STATIC_HTTP_DOWNLOAD, stub)
        service = FeedSyncOrchestrationService(session_factory, registry)

        run = await service.trigger_sync(
            feed_id=feed.id, trigger=FeedSyncTrigger.MANUAL, actor_id="admin-1"
        )
        assert run.status is FeedSyncRunStatus.SUCCEEDED
        assert run.retry_attempts_used == 3
        assert stub.call_count == 3

    async def test_permanent_failure_marks_run_failed_and_increments_feed_failure_count(
        self, session_factory
    ) -> None:
        feed = await _registered_active_feed(session_factory)
        registry = FeedConnectorRegistry()
        stub = _StubExecutor(fail_times=999, error_message="permanently broken")
        registry.register(FeedSourceKind.STATIC_HTTP_DOWNLOAD, stub)
        service = FeedSyncOrchestrationService(session_factory, registry)

        run = await service.trigger_sync(
            feed_id=feed.id, trigger=FeedSyncTrigger.MANUAL, actor_id="admin-1"
        )
        assert run.status is FeedSyncRunStatus.FAILED
        assert "permanently broken" in (run.error_message or "")
        assert run.retry_attempts_used == _FAST_RETRY.max_attempts

        query = FeedQueryService(session_factory)
        updated_feed = await query.get_feed(feed.id)
        assert updated_feed.consecutive_failure_count == 1
        assert updated_feed.checkpoint is None  # never advanced on failure

    async def test_sync_on_non_active_feed_raises(self, session_factory) -> None:
        admin = FeedAdminService(session_factory)
        feed = await admin.register_feed(
            actor_id="admin-1",
            feed_key=_unique_key("draft_orch_feed"),
            display_name="Draft Orchestration Feed",
            source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD.value,
            interval_seconds=600,
        )
        registry = FeedConnectorRegistry()
        registry.register(FeedSourceKind.STATIC_HTTP_DOWNLOAD, _StubExecutor())
        service = FeedSyncOrchestrationService(session_factory, registry)

        with pytest.raises(FeedNotActiveError):
            await service.trigger_sync(
                feed_id=feed.id, trigger=FeedSyncTrigger.MANUAL, actor_id="admin-1"
            )

    async def test_concurrent_triggers_for_the_same_feed_produce_exactly_one_run(
        self, session_factory
    ) -> None:
        """10 concurrent `trigger_sync` calls for the SAME feed — the
        per-feed PostgreSQL advisory lock plus the database's own
        partial unique index must together guarantee exactly one
        winner; every other caller observes `FeedSyncAlreadyRunningError`
        rather than a second concurrent run ever being created."""
        feed = await _registered_active_feed(session_factory)
        registry = FeedConnectorRegistry()
        # A slow stub widens the race window between "lock acquired,
        # run started" and "run finalized" so concurrent callers
        # genuinely overlap in time rather than serializing by luck.
        # The delay must comfortably exceed the time it takes all 10
        # contending `_start_run` transactions to cycle through the
        # per-feed advisory lock — a few DB round trips each — so no
        # caller can legitimately observe the first run as already
        # finished and start a second, independent one.
        stub = _SlowStubExecutor(delay_seconds=2.0, checkpoint="cursor-race")
        registry.register(FeedSourceKind.STATIC_HTTP_DOWNLOAD, stub)
        service = FeedSyncOrchestrationService(session_factory, registry)

        async def attempt() -> str:
            try:
                await service.trigger_sync(
                    feed_id=feed.id, trigger=FeedSyncTrigger.MANUAL, actor_id="admin-1"
                )
                return "ok"
            except FeedSyncAlreadyRunningError:
                return "already_running"

        results = await asyncio.gather(*(attempt() for _ in range(10)))
        assert results.count("ok") == 1, results
        assert results.count("already_running") == 9, results
        assert stub.call_count == 1

        query = FeedQueryService(session_factory)
        _, total_runs = await query.list_sync_runs(feed.id)
        assert total_runs == 1


class _SlowStubExecutor:
    def __init__(self, *, delay_seconds: float, checkpoint: str) -> None:
        self.delay_seconds = delay_seconds
        self.checkpoint = checkpoint
        self.call_count = 0

    async def execute(self, context: FeedSyncContext) -> FeedSyncOutcome:
        self.call_count += 1
        await asyncio.sleep(self.delay_seconds)
        return FeedSyncOutcome(checkpoint=self.checkpoint, items_fetched=1, items_processed=1)


# ─────────────────────────────────────────────────────────────────────────────
# Section E — HTTP acceptance
# ─────────────────────────────────────────────────────────────────────────────


class TestFeedSyncApiAuthorization:
    async def test_unauthenticated_request_is_401(self, client: AsyncClient) -> None:
        r = await client.get("/api/v1/threat-intel/feeds")
        assert r.status_code == 401

    async def test_authenticated_without_platform_role_is_403(
        self, client: AsyncClient, no_platform_role_token: str
    ) -> None:
        r = await client.get(
            "/api/v1/threat-intel/feeds",
            headers={"Authorization": f"Bearer {no_platform_role_token}"},
        )
        assert r.status_code == 403

    async def test_manage_endpoint_without_permission_is_403(
        self, client: AsyncClient, no_platform_role_token: str
    ) -> None:
        r = await client.post(
            "/api/v1/threat-intel/feeds",
            headers={"Authorization": f"Bearer {no_platform_role_token}"},
            json={
                "feed_key": _unique_key("rejected_feed"),
                "display_name": "Should Be Rejected",
                "source_kind": "static_http_download",
                "interval_seconds": 600,
            },
        )
        assert r.status_code == 403


class TestFeedSyncApiEndToEnd:
    async def test_register_activate_trigger_and_list_runs(
        self, client: AsyncClient, super_admin_token: str
    ) -> None:
        headers = {"Authorization": f"Bearer {super_admin_token}"}
        feed_key = _unique_key("api_feed")

        r = await client.post(
            "/api/v1/threat-intel/feeds",
            headers=headers,
            json={
                "feed_key": feed_key,
                "display_name": "API Test Feed",
                "source_kind": "static_http_download",
                "interval_seconds": 600,
            },
        )
        assert r.status_code == 201, r.text
        feed_id = r.json()["id"]
        assert r.json()["status"] == "draft"

        r = await client.post(
            f"/api/v1/threat-intel/feeds/{feed_id}/activate", headers=headers
        )
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "active"

        r = await client.get(f"/api/v1/threat-intel/feeds/{feed_id}", headers=headers)
        assert r.status_code == 200, r.text
        assert r.json()["feed_key"] == feed_key

        # No connector is registered for any FeedSourceKind via the HTTP
        # surface in Phase 2 — triggering sync must fail honestly with
        # 422, never a silent success.
        r = await client.post(f"/api/v1/threat-intel/feeds/{feed_id}/sync", headers=headers)
        assert r.status_code == 422, r.text

        r = await client.get(f"/api/v1/threat-intel/feeds/{feed_id}/runs", headers=headers)
        assert r.status_code == 200, r.text
        assert r.json()["total"] == 0

    async def test_list_feeds_supports_status_filter(
        self, client: AsyncClient, super_admin_token: str
    ) -> None:
        headers = {"Authorization": f"Bearer {super_admin_token}"}
        r = await client.get(
            "/api/v1/threat-intel/feeds", headers=headers, params={"status": "active"}
        )
        assert r.status_code == 200, r.text
        assert isinstance(r.json()["items"], list)

    async def test_get_unknown_feed_is_404(
        self, client: AsyncClient, super_admin_token: str
    ) -> None:
        headers = {"Authorization": f"Bearer {super_admin_token}"}
        r = await client.get("/api/v1/threat-intel/feeds/does-not-exist", headers=headers)
        assert r.status_code == 404

    async def test_pause_before_activate_is_409(
        self, client: AsyncClient, super_admin_token: str
    ) -> None:
        headers = {"Authorization": f"Bearer {super_admin_token}"}
        r = await client.post(
            "/api/v1/threat-intel/feeds",
            headers=headers,
            json={
                "feed_key": _unique_key("pause_conflict_feed"),
                "display_name": "Pause Conflict Feed",
                "source_kind": "manual_upload",
                "interval_seconds": 600,
            },
        )
        assert r.status_code == 201, r.text
        feed_id = r.json()["id"]

        r = await client.post(f"/api/v1/threat-intel/feeds/{feed_id}/pause", headers=headers)
        assert r.status_code == 409, r.text

    async def test_register_below_minimum_interval_is_422(
        self, client: AsyncClient, super_admin_token: str
    ) -> None:
        headers = {"Authorization": f"Bearer {super_admin_token}"}
        r = await client.post(
            "/api/v1/threat-intel/feeds",
            headers=headers,
            json={
                "feed_key": _unique_key("too_frequent_feed"),
                "display_name": "Too Frequent Feed",
                "source_kind": "static_http_download",
                "interval_seconds": 5,
            },
        )
        assert r.status_code == 422, r.text
