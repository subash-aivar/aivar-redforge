"""Real-PostgreSQL concurrency proof for M9 SecurityCorrelation
evaluation. Mirrors the exact pattern proven safe for M8
(`test_security_condition_race.py`) — isolated self-created database,
real asyncpg engine, no shared dev DB.
"""

from __future__ import annotations

import asyncio
import os

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.security_conditions.ingestion import SecurityConditionInput
from redforge.application.security_conditions.service import TenantSecurityConditionService
from redforge.application.security_correlation.rules import (
    CorrelationRuleRegistry,
    MultipleSecurityConditionsOnAssetRule,
)
from redforge.application.security_correlation.service import TenantSecurityCorrelationService
from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import AssetDiscoverySource, AssetType
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models.asset_connector import AIAssetModel
from redforge.infrastructure.database.models.security_conditions import SecurityConditionModel
from redforge.infrastructure.database.models.security_correlation import (
    SecurityCorrelationConditionModel,
    SecurityCorrelationEntityModel,
    SecurityCorrelationModel,
)
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio

_TEST_DB_NAME = "redforge_security_correlation_race_test"
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
        await conn.execute(
            text(
                "ALTER TABLE ai_assets ADD CONSTRAINT ux_ai_assets_id_org "
                "UNIQUE (id, organization_id)"
            )
        )
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[
                SecurityConditionModel.__table__, SecurityCorrelationModel.__table__,
                SecurityCorrelationConditionModel.__table__, SecurityCorrelationEntityModel.__table__,
            ],
        )
        await conn.execute(text("DELETE FROM security_correlation_conditions"))
        await conn.execute(text("DELETE FROM security_correlation_entities"))
        await conn.execute(text("DELETE FROM security_correlations"))
        await conn.execute(text("DELETE FROM security_conditions"))
        await conn.execute(text("DELETE FROM ai_assets"))

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory

    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS security_correlation_conditions CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS security_correlation_entities CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS security_correlations CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS security_conditions CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS ai_assets CASCADE"))
    await engine.dispose()


async def _make_host_with_two_conditions(asset_service, condition_service, org_id: str) -> str:
    host = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.HOST,
        scheme=IdentityScheme.DISCOVERY_HOST, raw_external_id=f"{EntityId.generate()}:race-host",
        name="race-host", description="", discovery_source=AssetDiscoverySource.API_SCAN,
    )
    await condition_service.ingest(SecurityConditionInput(
        organization_id=org_id, affected_asset_id=host.id, source_category="network_discovery",
        stable_rule_id="SENSITIVE_SERVICE_OBSERVED", evidence_state="observed", severity="medium",
        title="A", summary="A",
    ))
    await condition_service.ingest(SecurityConditionInput(
        organization_id=org_id, affected_asset_id=host.id, source_category="network_discovery",
        stable_rule_id="MULTIPLE_REMOTE_ADMIN_SERVICES", evidence_state="observed", severity="high",
        title="B", summary="B",
    ))
    return host.id


def _registry(condition_service) -> CorrelationRuleRegistry:
    registry = CorrelationRuleRegistry()
    registry.register(MultipleSecurityConditionsOnAssetRule(condition_service))
    return registry


async def test_concurrent_evaluation_produces_exactly_one_correlation(pg_factory) -> None:
    asset_service = TenantAssetService(pg_factory)
    condition_service = TenantSecurityConditionService(pg_factory)
    correlation_service = TenantSecurityCorrelationService(pg_factory, _registry(condition_service))
    org_id = str(EntityId.generate())
    await _make_host_with_two_conditions(asset_service, condition_service, org_id)

    await asyncio.gather(*(correlation_service.evaluate(org_id) for _ in range(8)))

    async with pg_factory() as session:
        result = await session.execute(
            select(func.count(SecurityCorrelationModel.id)).where(
                SecurityCorrelationModel.organization_id == org_id
            )
        )
        assert result.scalar_one() == 1


async def test_same_identity_across_two_tenants_remains_separate(pg_factory) -> None:
    asset_service = TenantAssetService(pg_factory)
    condition_service = TenantSecurityConditionService(pg_factory)
    correlation_service = TenantSecurityCorrelationService(pg_factory, _registry(condition_service))
    org_a, org_b = str(EntityId.generate()), str(EntityId.generate())
    await _make_host_with_two_conditions(asset_service, condition_service, org_a)
    await _make_host_with_two_conditions(asset_service, condition_service, org_b)

    await correlation_service.evaluate(org_a)
    await correlation_service.evaluate(org_b)

    corr_a = await correlation_service.list_for_org(org_a)
    corr_b = await correlation_service.list_for_org(org_b)
    assert len(corr_a) == 1
    assert len(corr_b) == 1
    assert corr_a[0].id != corr_b[0].id


async def test_title_summary_operator_action_update_does_not_duplicate(pg_factory) -> None:
    asset_service = TenantAssetService(pg_factory)
    condition_service = TenantSecurityConditionService(pg_factory)
    correlation_service = TenantSecurityCorrelationService(pg_factory, _registry(condition_service))
    org_id = str(EntityId.generate())
    host_id = await _make_host_with_two_conditions(asset_service, condition_service, org_id)

    await correlation_service.evaluate(org_id)
    first_id = (await correlation_service.list_for_org(org_id))[0].id

    # Add a third condition — summary text changes (count 2->3) but the
    # correlation identity (org + rule + [host_id]) is unaffected.
    await condition_service.ingest(SecurityConditionInput(
        organization_id=org_id, affected_asset_id=host_id, source_category="cloud_configuration",
        stable_rule_id="PUBLIC_STORAGE_CONFIGURATION", evidence_state="observed", severity="high",
        title="C", summary="C",
    ))
    await correlation_service.evaluate(org_id)
    second_id = (await correlation_service.list_for_org(org_id))[0].id

    assert first_id == second_id
    async with pg_factory() as session:
        result = await session.execute(
            select(func.count(SecurityCorrelationModel.id)).where(
                SecurityCorrelationModel.organization_id == org_id
            )
        )
        assert result.scalar_one() == 1


async def test_resolve_then_reobserve_reactivates_same_correlation(pg_factory) -> None:
    asset_service = TenantAssetService(pg_factory)
    condition_service = TenantSecurityConditionService(pg_factory)
    correlation_service = TenantSecurityCorrelationService(pg_factory, _registry(condition_service))
    org_id = str(EntityId.generate())
    host = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.HOST,
        scheme=IdentityScheme.DISCOVERY_HOST, raw_external_id=f"{EntityId.generate()}:reobs-host",
        name="reobs-host", description="", discovery_source=AssetDiscoverySource.API_SCAN,
    )
    cond_1 = await condition_service.ingest(SecurityConditionInput(
        organization_id=org_id, affected_asset_id=host.id, source_category="network_discovery",
        stable_rule_id="SENSITIVE_SERVICE_OBSERVED", evidence_state="observed", severity="medium",
        title="A", summary="A",
    ))
    await condition_service.ingest(SecurityConditionInput(
        organization_id=org_id, affected_asset_id=host.id, source_category="network_discovery",
        stable_rule_id="MULTIPLE_REMOTE_ADMIN_SERVICES", evidence_state="observed", severity="high",
        title="B", summary="B",
    ))
    await correlation_service.evaluate(org_id)
    correlation_id = (await correlation_service.list_for_org(org_id, lifecycle="active"))[0].id

    await condition_service.resolve_condition(cond_1.id, org_id)
    await correlation_service.evaluate(org_id)
    assert (await correlation_service.get_for_org(correlation_id, org_id)).lifecycle == "resolved"

    await condition_service.ingest(SecurityConditionInput(
        organization_id=org_id, affected_asset_id=host.id, source_category="network_discovery",
        stable_rule_id="SENSITIVE_SERVICE_OBSERVED", evidence_state="observed", severity="medium",
        title="A", summary="A",
    ))
    await correlation_service.evaluate(org_id)
    reactivated = await correlation_service.get_for_org(correlation_id, org_id)
    assert reactivated.lifecycle == "active"
    assert reactivated.id == correlation_id

    async with pg_factory() as session:
        result = await session.execute(
            select(func.count(SecurityCorrelationModel.id)).where(
                SecurityCorrelationModel.organization_id == org_id
            )
        )
        assert result.scalar_one() == 1
