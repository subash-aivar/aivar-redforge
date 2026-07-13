"""Real-PostgreSQL concurrency proof for MFA enrollment — M2.

Proves that concurrent `begin_enrollment` calls for the SAME user cannot
produce two PENDING_ENROLLMENT rows — enforced by the partial unique
index `ux_mfa_factors_user_status_pending` (migration 0012), not by the
application-level delete-then-insert alone (which reduces but does not
by itself eliminate the race window under true concurrency).

Runs against a dedicated, self-created database
(`redforge_mfa_race_test`), never the shared dev database — same
isolation pattern as tests/integration/test_platform_identity_bootstrap_race.py.
"""

from __future__ import annotations

import asyncio
import os

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.mfa import MFAService
from redforge.domain.mfa.exceptions import MFAAlreadyActiveError
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models.mfa import MFAFactorModel
from redforge.infrastructure.database.models.platform_identity import (
    PlatformAuditLogModel,
)

pytestmark = pytest.mark.asyncio

_TEST_DB_NAME = "redforge_mfa_race_test"
_TEST_MFA_KEY = "JCBz3tgnOeWF7cKJJpMOD9iTL4pc0h9KLX3kgCyj-9g="
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
        _MAINTENANCE_DB_URL, echo=False, isolation_level="AUTOCOMMIT",
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
            tables=[MFAFactorModel.__table__, PlatformAuditLogModel.__table__],
        )
        await conn.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "ux_mfa_factors_user_status_active_test "
                "ON mfa_factors (user_id, status) WHERE status = 'active'"
            )
        )
        await conn.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "ux_mfa_factors_user_status_pending_test "
                "ON mfa_factors (user_id, status) WHERE status = 'pending_enrollment'"
            )
        )
        await conn.execute(text("DELETE FROM mfa_factors"))
        await conn.execute(text("DELETE FROM platform_audit_log"))

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory

    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS platform_audit_log CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS mfa_factors CASCADE"))
    await engine.dispose()


async def test_concurrent_begin_enrollment_never_produces_two_pending_rows(pg_factory):
    """10 concurrent begin_enrollment calls for the same user — the
    partial unique index guarantees at most one PENDING_ENROLLMENT row
    survives, regardless of how the delete-then-insert race interleaves.
    """
    service = MFAService(pg_factory, _TEST_MFA_KEY)

    async def attempt() -> str:
        try:
            result = await service.begin_enrollment("user-concurrent", "user@redforge.test")
            return f"success:{result.enrollment_id}"
        except Exception as exc:
            return f"error:{type(exc).__name__}"

    results = await asyncio.gather(*(attempt() for _ in range(10)))

    async with pg_factory() as session:
        result = await session.execute(
            select(func.count(MFAFactorModel.id)).where(
                MFAFactorModel.user_id == "user-concurrent",
                MFAFactorModel.status == "pending_enrollment",
            )
        )
        pending_count = result.scalar_one()

    assert pending_count == 1, (
        f"expected exactly 1 pending enrollment row after concurrent "
        f"begin_enrollment calls, found {pending_count} (results={results})"
    )


async def test_concurrent_enrollment_when_already_active_all_denied(pg_factory):
    """Once ACTIVE, concurrent begin_enrollment attempts must ALL be
    rejected (MFAAlreadyActiveError) — none should silently create a
    second pending factor alongside the active one.
    """
    service = MFAService(pg_factory, _TEST_MFA_KEY)
    enrolled = await service.begin_enrollment("user-active", "user2@redforge.test")

    import pyotp

    totp = pyotp.TOTP(enrolled.secret)
    await service.verify_and_activate("user-active", enrolled.enrollment_id, totp.now())

    async def attempt() -> str:
        try:
            await service.begin_enrollment("user-active", "user2@redforge.test")
            return "success"
        except MFAAlreadyActiveError:
            return "denied"

    results = await asyncio.gather(*(attempt() for _ in range(5)))
    assert all(r == "denied" for r in results)
