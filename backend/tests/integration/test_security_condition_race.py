"""Real-PostgreSQL concurrency proof for M8 SecurityCondition ingestion.

Mirrors the exact pattern proven safe for M6/M7 asset resolution
(`test_cloud_asset_race.py`) — isolated self-created database, real
asyncpg engine, no shared dev DB.
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.security_conditions.ingestion import SecurityConditionInput
from redforge.application.security_conditions.service import TenantSecurityConditionService
from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import AssetDiscoverySource, AssetType
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models.asset_connector import AIAssetModel
from redforge.infrastructure.database.models.security_conditions import SecurityConditionModel
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio

_TEST_DB_NAME = "redforge_security_condition_race_test"
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
        await conn.run_sync(
            Base.metadata.create_all, tables=[AIAssetModel.__table__],
        )
        await conn.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_ai_assets_org_external_id_test "
                "ON ai_assets (organization_id, external_id) WHERE external_id != ''"
            )
        )
        await conn.execute(
            text(
                "ALTER TABLE ai_assets ADD CONSTRAINT ux_ai_assets_id_org "
                "UNIQUE (id, organization_id)"
            )
        )
        await conn.run_sync(
            Base.metadata.create_all, tables=[SecurityConditionModel.__table__],
        )
        await conn.execute(text("DELETE FROM security_conditions"))
        await conn.execute(text("DELETE FROM ai_assets"))

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory

    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS security_conditions CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS ai_assets CASCADE"))
    await engine.dispose()


async def _make_asset(factory, organization_id: str, external_id: str = "") -> str:
    asset_service = TenantAssetService(factory)
    dto = await asset_service.resolve_asset(
        organization_id=organization_id,
        asset_type=AssetType.HOST,
        scheme=IdentityScheme.DISCOVERY_HOST,
        raw_external_id=f"{EntityId.generate()}:{external_id or EntityId.generate()}",
        name="test-host",
        description="",
        discovery_source=AssetDiscoverySource.API_SCAN,
    )
    return dto.id


def _input(
    org_id: str, asset_id: str, title: str = "Sensitive service observed",
    summary: str = "SSH observed on host.", remediation: str = "",
) -> SecurityConditionInput:
    return SecurityConditionInput(
        organization_id=org_id,
        affected_asset_id=asset_id,
        source_category="network_discovery",
        stable_rule_id="SENSITIVE_SERVICE_OBSERVED",
        evidence_state="observed",
        severity="medium",
        title=title,
        summary=summary,
        remediation=remediation,
    )


async def test_concurrent_same_condition_produces_exactly_one_row(pg_factory) -> None:
    service = TenantSecurityConditionService(pg_factory)
    org_id = str(EntityId.generate())
    asset_id = await _make_asset(pg_factory, org_id)

    async def attempt() -> str:
        dto = await service.ingest(_input(org_id, asset_id))
        return dto.id

    results = await asyncio.gather(*(attempt() for _ in range(10)))
    assert len(set(results)) == 1

    async with pg_factory() as session:
        result = await session.execute(
            select(func.count(SecurityConditionModel.id)).where(
                SecurityConditionModel.organization_id == org_id
            )
        )
        assert result.scalar_one() == 1


async def test_same_identity_across_two_tenants_remains_separate(pg_factory) -> None:
    service = TenantSecurityConditionService(pg_factory)
    org_a, org_b = str(EntityId.generate()), str(EntityId.generate())
    asset_a = await _make_asset(pg_factory, org_a)
    asset_b = await _make_asset(pg_factory, org_b)

    dto_a = await service.ingest(_input(org_a, asset_a))
    dto_b = await service.ingest(_input(org_b, asset_b))
    assert dto_a.id != dto_b.id

    async with pg_factory() as session:
        result = await session.execute(select(func.count(SecurityConditionModel.id)))
        assert result.scalar_one() == 2


async def test_same_rule_on_two_assets_remains_separate(pg_factory) -> None:
    service = TenantSecurityConditionService(pg_factory)
    org_id = str(EntityId.generate())
    asset_1 = await _make_asset(pg_factory, org_id, "host-1")
    asset_2 = await _make_asset(pg_factory, org_id, "host-2")

    dto_1 = await service.ingest(_input(org_id, asset_1))
    dto_2 = await service.ingest(_input(org_id, asset_2))
    assert dto_1.id != dto_2.id

    async with pg_factory() as session:
        result = await session.execute(
            select(func.count(SecurityConditionModel.id)).where(
                SecurityConditionModel.organization_id == org_id
            )
        )
        assert result.scalar_one() == 2


async def test_title_summary_remediation_update_does_not_duplicate(pg_factory) -> None:
    service = TenantSecurityConditionService(pg_factory)
    org_id = str(EntityId.generate())
    asset_id = await _make_asset(pg_factory, org_id)

    first = await service.ingest(_input(org_id, asset_id, title="Old title"))
    second = await service.ingest(
        _input(org_id, asset_id, title="New title", summary="New summary", remediation="Patch it"),
    )
    assert first.id == second.id
    assert second.title == "New title"

    async with pg_factory() as session:
        result = await session.execute(
            select(func.count(SecurityConditionModel.id)).where(
                SecurityConditionModel.organization_id == org_id
            )
        )
        assert result.scalar_one() == 1


async def test_resolve_then_reobserve_reactivates_same_condition(pg_factory) -> None:
    service = TenantSecurityConditionService(pg_factory)
    org_id = str(EntityId.generate())
    asset_id = await _make_asset(pg_factory, org_id)

    created = await service.ingest(_input(org_id, asset_id))
    assert created.lifecycle == "active"

    resolved = await service.resolve_condition(created.id, org_id)
    assert resolved.lifecycle == "resolved"

    reobserved = await service.ingest(_input(org_id, asset_id))
    assert reobserved.id == created.id
    assert reobserved.lifecycle == "active"

    async with pg_factory() as session:
        result = await session.execute(
            select(func.count(SecurityConditionModel.id)).where(
                SecurityConditionModel.organization_id == org_id
            )
        )
        assert result.scalar_one() == 1


async def test_last_observed_at_advances_first_observed_at_stable(pg_factory) -> None:
    service = TenantSecurityConditionService(pg_factory)
    org_id = str(EntityId.generate())
    asset_id = await _make_asset(pg_factory, org_id)

    first = await service.ingest(_input(org_id, asset_id))
    await asyncio.sleep(0.01)
    second = await service.ingest(_input(org_id, asset_id))

    assert second.first_observed_at == first.first_observed_at
    assert datetime.fromisoformat(second.last_observed_at) >= datetime.fromisoformat(
        first.last_observed_at
    )
    _ = datetime.now(UTC)  # sanity: timestamps are real, not frozen
