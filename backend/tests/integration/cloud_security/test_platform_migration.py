"""Alembic migration round-trip for M26 Phase 8 (0053 Cloud Platform)."""

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

_PLATFORM_TABLES = (
    "cloud_orchestration_runs",
    "cloud_platform_validation_reports",
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


@pytest.mark.parametrize("table", _PLATFORM_TABLES)
def test_platform_tables_exist_after_upgrade(table: str) -> None:
    if not os.environ.get("TEST_DATABASE_URL"):
        pytest.skip("TEST_DATABASE_URL not set")
    _run_alembic("0053")
    assert asyncio.run(_table_exists(table))


def test_platform_migration_head() -> None:
    if not os.environ.get("TEST_DATABASE_URL"):
        pytest.skip("TEST_DATABASE_URL not set")
    _run_alembic("0053")
    assert asyncio.run(_alembic_head()) == "0053"


def test_platform_migration_round_trip() -> None:
    if not os.environ.get("TEST_DATABASE_URL"):
        pytest.skip("TEST_DATABASE_URL not set")
    _run_alembic("0053")
    assert asyncio.run(_table_exists("cloud_orchestration_runs"))
    _run_alembic("downgrade:0052")
    assert not asyncio.run(_table_exists("cloud_orchestration_runs"))
    _run_alembic("0053")
    assert asyncio.run(_table_exists("cloud_orchestration_runs"))
    assert asyncio.run(_alembic_head()) == "0053"
