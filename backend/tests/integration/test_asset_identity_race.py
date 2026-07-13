"""Real-PostgreSQL concurrency proof for asset identity resolution — M3.

Proves the two mandatory M3 concurrency invariants:
  1. Concurrent discovery of the SAME (organization_id, external_id)
     produces exactly one canonical asset — enforced by the partial
     unique index `ux_ai_assets_org_external_id` (migration 0013), not
     an application-level check-then-insert.
  2. The SAME external identity in two DIFFERENT organizations produces
     two fully independent canonical assets — tenant isolation holds
     even when the external identity string collides.

Runs against a dedicated, self-created database
(`redforge_asset_race_test`), never the shared dev database.
"""

from __future__ import annotations

import asyncio
import os

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models.asset_connector import AIAssetModel
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio

_TEST_DB_NAME = "redforge_asset_race_test"
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
        await conn.run_sync(Base.metadata.create_all, tables=[AIAssetModel.__table__])
        await conn.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "ux_ai_assets_org_external_id_test "
                "ON ai_assets (organization_id, external_id) WHERE external_id != ''"
            )
        )
        await conn.execute(text("DELETE FROM ai_assets"))

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory

    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS ai_assets CASCADE"))
    await engine.dispose()


async def test_concurrent_same_identity_produces_exactly_one_asset(pg_factory):
    """10 concurrent get_or_create_for_target calls for the SAME
    (org, target_id) — exactly one canonical asset must exist afterward,
    verified against the database, not in-process results.
    """
    service = TenantAssetService(pg_factory)
    org_id = str(EntityId.generate())
    target_id = str(EntityId.generate())

    async def attempt() -> str:
        dto = await service.get_or_create_for_target(
            organization_id=org_id,
            target_id=target_id,
            target_name="Concurrent Target",
            target_type="ai_api",
        )
        return dto.id

    results = await asyncio.gather(*(attempt() for _ in range(10)))

    # All 10 calls must resolve to the SAME asset ID.
    assert len(set(results)) == 1, f"expected 1 unique asset id, got {set(results)}"

    async with pg_factory() as session:
        result = await session.execute(
            select(func.count(AIAssetModel.id)).where(
                AIAssetModel.organization_id == org_id,
            )
        )
        count = result.scalar_one()
    assert count == 1, f"expected exactly 1 persisted asset row, found {count}"


async def test_same_external_identity_across_orgs_remains_separate(pg_factory):
    """The identical target_id, resolved for two DIFFERENT organizations
    concurrently, must produce two independent canonical assets — the
    tenant-scoped unique index is (organization_id, external_id), not
    external_id alone.
    """
    service = TenantAssetService(pg_factory)
    target_id = str(EntityId.generate())
    org_a = str(EntityId.generate())
    org_b = str(EntityId.generate())

    async def create_for(org_id: str) -> str:
        dto = await service.get_or_create_for_target(
            organization_id=org_id,
            target_id=target_id,
            target_name="Shared-ID Target",
            target_type="ai_api",
        )
        return dto.id

    results = await asyncio.gather(
        *(create_for(org_a) for _ in range(5)),
        *(create_for(org_b) for _ in range(5)),
    )

    a_ids = {r for i, r in enumerate(results) if i < 5}
    b_ids = {r for i, r in enumerate(results) if i >= 5}
    assert len(a_ids) == 1
    assert len(b_ids) == 1
    assert a_ids != b_ids, "org A and org B must never resolve to the same asset"

    async with pg_factory() as session:
        result = await session.execute(select(func.count(AIAssetModel.id)))
        total = result.scalar_one()
    assert total == 2, f"expected exactly 2 assets total (1 per org), found {total}"
