"""Alembic migration round-trip for M26 Phase 7 (0052 Cloud Risk)."""

from __future__ import annotations

import asyncio
import os
import warnings

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

pytestmark = pytest.mark.integration

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)

_RISK_TABLES = (
    "cloud_risk_scores",
    "cloud_risk_history",
    "cloud_risk_factors",
    "cloud_risk_exposures",
    "cloud_risk_assessments",
)


def _run_alembic(*targets: str) -> None:
    os.environ["REDFORGE_DATABASE_URL"] = TEST_DATABASE_URL
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        cfg = Config("alembic.ini")
        for target in targets:
            if target.startswith("downgrade:"):
                command.downgrade(cfg, target.removeprefix("downgrade:"))
            else:
                command.upgrade(cfg, target)


async def _table_exists(table: str) -> bool:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = 'cloud_security' AND table_name = :t"
                ),
                {"t": table},
            )
            return result.scalar_one_or_none() is not None
    finally:
        await engine.dispose()


async def _alembic_head() -> str | None:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT version_num FROM alembic_version LIMIT 1"))
            value = result.scalar_one_or_none()
            return str(value) if value is not None else None
    finally:
        await engine.dispose()


async def _unique_exists() -> bool:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT 1 FROM pg_constraint "
                    "WHERE conname = 'uq_cloud_risk_scores_org_asset'"
                )
            )
            return result.scalar_one_or_none() is not None
    finally:
        await engine.dispose()


def test_risk_migration_0052_round_trip() -> None:
    """Sync test — Alembic env uses asyncio.run and cannot nest under pytest-asyncio."""
    if not os.environ.get("TEST_DATABASE_URL"):
        pytest.skip("TEST_DATABASE_URL not set")

    _run_alembic("0052")
    assert asyncio.run(_alembic_head()) == "0052"
    for table in _RISK_TABLES:
        assert asyncio.run(_table_exists(table)), f"expected {table} after upgrade to 0052"
    assert asyncio.run(_unique_exists())

    _run_alembic("downgrade:0051")
    assert asyncio.run(_alembic_head()) == "0051"
    for table in _RISK_TABLES:
        assert not asyncio.run(_table_exists(table)), f"expected {table} dropped after downgrade"

    _run_alembic("0052")
    assert asyncio.run(_alembic_head()) == "0052"
    for table in _RISK_TABLES:
        assert asyncio.run(_table_exists(table)), f"expected {table} after re-upgrade to 0052"
