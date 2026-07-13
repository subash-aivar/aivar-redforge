"""Real-PostgreSQL concurrency proof for M6 network asset resolution.

Reuses the exact M3 `ai_assets` table/unique-index (migration 0013) —
no new migration was needed for M6, since NETWORK/IP_ADDRESS/HOST/
DEVICE/SERVICE are canonical AssetType kinds resolved through the same
`TenantAssetService.resolve_asset` race-safe upsert path M3 already
proved safe for REDFORGE_TARGET_ID. This test proves the same
invariant holds for the new M6 identity schemes.
"""

from __future__ import annotations

import asyncio
import os

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import AssetDiscoverySource, AssetType
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models.asset_connector import AIAssetModel
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio

_TEST_DB_NAME = "redforge_network_asset_race_test"
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
                text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": _TEST_DB_NAME},
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
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_ai_assets_org_external_id_test "
                "ON ai_assets (organization_id, external_id) WHERE external_id != ''"
            )
        )
        await conn.execute(text("DELETE FROM ai_assets"))

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory

    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS ai_assets CASCADE"))
    await engine.dispose()


async def test_concurrent_same_ip_resolution_produces_exactly_one_asset(pg_factory):
    service = TenantAssetService(pg_factory)
    org_id = str(EntityId.generate())

    async def attempt() -> str:
        dto = await service.resolve_asset(
            organization_id=org_id, asset_type=AssetType.IP_ADDRESS,
            scheme=IdentityScheme.IP_ADDRESS, raw_external_id="10.0.0.5",
            name="10.0.0.5", description="test",
            discovery_source=AssetDiscoverySource.API_SCAN,
        )
        return dto.id

    results = await asyncio.gather(*(attempt() for _ in range(10)))
    assert len(set(results)) == 1

    async with pg_factory() as session:
        result = await session.execute(
            select(func.count(AIAssetModel.id)).where(AIAssetModel.organization_id == org_id)
        )
        assert result.scalar_one() == 1


async def test_same_ip_across_orgs_remains_separate(pg_factory):
    service = TenantAssetService(pg_factory)
    org_a = str(EntityId.generate())
    org_b = str(EntityId.generate())

    async def resolve_for(org_id: str) -> str:
        dto = await service.resolve_asset(
            organization_id=org_id, asset_type=AssetType.IP_ADDRESS,
            scheme=IdentityScheme.IP_ADDRESS, raw_external_id="192.168.1.1",
            name="192.168.1.1", description="test",
            discovery_source=AssetDiscoverySource.API_SCAN,
        )
        return dto.id

    results = await asyncio.gather(
        *(resolve_for(org_a) for _ in range(5)), *(resolve_for(org_b) for _ in range(5)),
    )
    a_ids = {r for i, r in enumerate(results) if i < 5}
    b_ids = {r for i, r in enumerate(results) if i >= 5}
    assert len(a_ids) == 1
    assert len(b_ids) == 1
    assert a_ids != b_ids

    async with pg_factory() as session:
        result = await session.execute(select(func.count(AIAssetModel.id)))
        assert result.scalar_one() == 2


async def test_concurrent_same_service_endpoint_resolution_produces_exactly_one_asset(pg_factory):
    service = TenantAssetService(pg_factory)
    org_id = str(EntityId.generate())
    host_asset = await service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.HOST,
        scheme=IdentityScheme.DISCOVERY_HOST, raw_external_id="conn-1:host.example.com",
        name="host.example.com", description="test",
        discovery_source=AssetDiscoverySource.API_SCAN,
    )

    async def attempt() -> str:
        dto = await service.resolve_asset(
            organization_id=org_id, asset_type=AssetType.SERVICE,
            scheme=IdentityScheme.SERVICE_ENDPOINT,
            raw_external_id=f"{host_asset.id}:tcp:22",
            name="ssh", description="test",
            discovery_source=AssetDiscoverySource.API_SCAN,
        )
        return dto.id

    results = await asyncio.gather(*(attempt() for _ in range(10)))
    assert len(set(results)) == 1

    async with pg_factory() as session:
        result = await session.execute(
            select(func.count(AIAssetModel.id)).where(
                AIAssetModel.organization_id == org_id, AIAssetModel.asset_type == "service",
            )
        )
        assert result.scalar_one() == 1
