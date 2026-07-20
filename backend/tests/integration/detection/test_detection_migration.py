"""Alembic migration round-trip for M28 Phase 1 (0058)."""

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

_DETECTION_TABLES = (
    "detection_rules",
    "rule_versions",
    "rule_test_cases",
    "rule_test_results",
    "rule_mitre_mappings",
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
                    "WHERE table_schema = 'detection' AND table_name = :t"
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
            result = await conn.execute(
                text("SELECT version_num FROM alembic_version LIMIT 1")
            )
            value = result.scalar_one_or_none()
            return str(value) if value is not None else None
    finally:
        await engine.dispose()


async def _schema_exists() -> bool:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT 1 FROM information_schema.schemata "
                    "WHERE schema_name = 'detection'"
                )
            )
            return result.scalar_one_or_none() is not None
    finally:
        await engine.dispose()


def test_detection_migration_0058_round_trip() -> None:
    """Sync test — Alembic env uses asyncio.run and cannot nest under pytest-asyncio."""
    if not os.environ.get("TEST_DATABASE_URL"):
        pytest.skip("TEST_DATABASE_URL not set")

    _run_alembic("0058")
    assert asyncio.run(_alembic_head()) == "0058"
    assert asyncio.run(_schema_exists())
    for table in _DETECTION_TABLES:
        assert asyncio.run(_table_exists(table)), (
            f"expected {table} after upgrade to 0058"
        )

    _run_alembic("downgrade:0057")
    assert asyncio.run(_alembic_head()) == "0057"
    for table in _DETECTION_TABLES:
        assert not asyncio.run(_table_exists(table)), (
            f"expected {table} dropped after downgrade"
        )
    assert not asyncio.run(_schema_exists()), (
        "expected detection schema dropped after downgrade to 0057"
    )

    _run_alembic("0058")
    assert asyncio.run(_alembic_head()) == "0058"
    for table in _DETECTION_TABLES:
        assert asyncio.run(_table_exists(table)), (
            f"expected {table} after re-upgrade to 0058"
        )
