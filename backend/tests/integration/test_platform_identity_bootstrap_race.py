"""Real-PostgreSQL race-safety proof for platform Super Admin bootstrap
and last-Super-Admin revoke protection — M1.

These specifically require PostgreSQL: SQLite does not give the same
row-locking/transaction-isolation guarantees this test asserts on, and
the migration's partial unique index (`postgresql_where=...`) is a
no-op on SQLite.

Runs against a DEDICATED, self-created database
(`redforge_platform_race_test` by default), never against the shared
dev `redforge` database — that database carries the real
migration-managed `platform_assignments`/etc. tables once migration
0011 is applied, and this fixture's create/drop-table lifecycle would
otherwise collide with them (as happened once during M1 development:
see git history / M1 report for the incident). The fixture creates the
database if missing and drops all three tables (not just rows) at
teardown, leaving no residue in either the maintenance connection or
the test database.
"""

from __future__ import annotations

import asyncio
import os

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.platform_identity import PlatformAccessService
from redforge.core.config import Settings
from redforge.domain.platform_identity.exceptions import (
    BootstrapAlreadyConsumedError,
    LastSuperAdminProtectionError,
)
from redforge.domain.platform_identity.value_objects import PlatformRole
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (
    PlatformAssignmentModel,
    PlatformAuditLogModel,
    PlatformBootstrapStateModel,
)

pytestmark = pytest.mark.asyncio

_TEST_DB_NAME = "redforge_platform_race_test"
_MAINTENANCE_DB_URL = os.environ.get(
    "REDFORGE_MAINTENANCE_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/postgres",
)
_DB_URL = os.environ.get(
    "REDFORGE_TEST_DATABASE_URL",
    f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_TEST_DB_NAME}",
)


async def _ensure_test_database_exists() -> None:
    maintenance_engine = create_async_engine(
        _MAINTENANCE_DB_URL, echo=False, isolation_level="AUTOCOMMIT"
    )
    try:
        async with maintenance_engine.connect() as conn:
            exists = await conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"),
                {"name": _TEST_DB_NAME},
            )
            if exists.first() is None:
                await conn.execute(text(f'CREATE DATABASE "{_TEST_DB_NAME}"'))
    finally:
        await maintenance_engine.dispose()


@pytest.fixture
async def pg_factory():
    await _ensure_test_database_exists()

    engine = create_async_engine(_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[
                PlatformAssignmentModel.__table__,
                PlatformAuditLogModel.__table__,
                PlatformBootstrapStateModel.__table__,
            ],
        )
        await conn.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "ux_platform_assignments_user_role_active_test "
                "ON platform_assignments (user_id, role) WHERE status = 'active'"
            )
        )
        await conn.execute(text("DELETE FROM platform_assignments"))
        await conn.execute(text("DELETE FROM platform_audit_log"))
        await conn.execute(text("DELETE FROM platform_bootstrap_state"))
        await conn.execute(
            text(
                "INSERT INTO platform_bootstrap_state (id, consumed_at, consumed_by) "
                "VALUES ('singleton', NULL, NULL)"
            )
        )

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory

    # Drop the tables entirely (not just rows) — this database exists
    # solely for this test file and must never accumulate schema drift
    # across runs or be mistaken for a migration-managed database.
    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS platform_audit_log CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS platform_assignments CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS platform_bootstrap_state CASCADE"))
    await engine.dispose()


def _settings() -> Settings:
    return Settings(
        environment="test",
        jwt_secret="test-secret-key-that-is-long-enough-32!",
        platform_bootstrap_enabled=True,
        platform_bootstrap_principal_email="owner@redforge.test",
    )


async def test_concurrent_bootstrap_attempts_produce_exactly_one_super_admin(
    pg_factory,
):
    """Fires 10 concurrent bootstrap attempts for the same principal.
    Exactly one must succeed; the rest must fail with
    BootstrapAlreadyConsumedError — proven against real PostgreSQL row
    locking on the platform_bootstrap_state singleton row, not an
    app-level `if count == 0` check.
    """
    service = PlatformAccessService(pg_factory, _settings())

    async def attempt() -> str:
        try:
            dto = await service.bootstrap_super_admin("user-concurrent", "owner@redforge.test")
            return f"success:{dto.id}"
        except BootstrapAlreadyConsumedError:
            return "denied"

    results = await asyncio.gather(*(attempt() for _ in range(10)))

    successes = [r for r in results if r.startswith("success")]
    denials = [r for r in results if r == "denied"]
    assert len(successes) == 1, f"expected exactly 1 success, got {len(successes)}: {results}"
    assert len(denials) == 9

    # Verify exactly one ACTIVE assignment exists in the database — the
    # real, final proof (not just the in-process return values).
    async with pg_factory() as session:
        result = await session.execute(
            text(
                "SELECT count(*) FROM platform_assignments "
                "WHERE role = 'platform_super_admin' AND status = 'active'"
            )
        )
        assert result.scalar_one() == 1


async def test_concurrent_bootstrap_different_principals_only_one_wins(pg_factory):
    """Two different (simulated) principal identities racing the same
    bootstrap slot — still exactly one winner, because the claim is on
    the singleton row, not per-principal.
    """
    service = PlatformAccessService(pg_factory, _settings())

    async def attempt(user_id: str) -> str:
        try:
            await service.bootstrap_super_admin(user_id, "owner@redforge.test")
            return f"success:{user_id}"
        except BootstrapAlreadyConsumedError:
            return f"denied:{user_id}"

    results = await asyncio.gather(
        attempt("user-a"), attempt("user-b"), attempt("user-c"), attempt("user-d")
    )
    successes = [r for r in results if r.startswith("success")]
    assert len(successes) == 1


async def test_concurrent_revoke_of_two_last_super_admins_protects_one(pg_factory):
    """Two active Super Admins exist. Firing concurrent revokes at BOTH
    simultaneously must leave exactly one active — the second revoke to
    reach the row lock must observe the first's committed state and
    refuse, rather than both succeeding and leaving zero Super Admins.
    """
    service = PlatformAccessService(pg_factory, _settings())

    first = await service.bootstrap_super_admin("owner-1", "owner@redforge.test")

    second = await service.grant(
        target_user_id="owner-2",
        role=PlatformRole.SUPER_ADMIN,
        granted_by="owner-1",
    )

    async def revoke(assignment_id: str) -> str:
        try:
            await service.revoke(assignment_id, revoked_by="owner-1")
            return "revoked"
        except LastSuperAdminProtectionError:
            return "protected"

    results = await asyncio.gather(revoke(first.id), revoke(second.id))

    # At least one revoke must be protected — zero active Super Admins
    # must never be reachable via concurrent revokes.
    async with pg_factory() as session:
        result = await session.execute(
            text(
                "SELECT count(*) FROM platform_assignments "
                "WHERE role = 'platform_super_admin' AND status = 'active'"
            )
        )
        active_count = result.scalar_one()
    assert active_count >= 1, (
        f"concurrent revoke left {active_count} active Super Admins — "
        f"last-Super-Admin protection failed under concurrency (results={results})"
    )
