"""End-to-end correlation evaluation proof — M9.

Uses SQLite for correctness/lifecycle proof (mirrors the M8
`test_security_condition_race.py` split: SQLite here for behavior,
dedicated PostgreSQL file for real concurrency). Exercises both
implemented rules against real canonical facts built through the
legitimate TenantAssetService/TenantSecurityConditionService paths —
never fabricated rows.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.security_conditions.ingestion import SecurityConditionInput
from redforge.application.security_conditions.service import TenantSecurityConditionService
from redforge.application.security_correlation.rules import (
    CorrelationRuleRegistry,
    MultipleSecurityConditionsOnAssetRule,
    PublicSensitiveServiceContextRule,
)
from redforge.application.security_correlation.service import TenantSecurityCorrelationService
from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import (
    AssetDiscoverySource,
    AssetRelationshipType,
    AssetType,
)
from redforge.infrastructure.database.base import Base
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def factory():
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        # Excludes tables using raw postgresql.JSONB (platform_events,
        # platform_snapshots, platform_read_models, dead_letter_entries)
        # — those don't compile against SQLite. A whole-metadata
        # create_all() only "worked" before by luck of import order (this
        # test never touches those tables); scoping explicitly makes it
        # correct regardless of what else has been imported this session.
        sqlite_safe_tables = [
            t for t in Base.metadata.sorted_tables
            if t.name not in {
                "platform_events", "platform_snapshots",
                "platform_read_models", "dead_letter_entries",
            }
        ]
        await conn.run_sync(Base.metadata.create_all, tables=sqlite_safe_tables)
    yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    await engine.dispose()


def _registry(asset_service, condition_service) -> CorrelationRuleRegistry:
    registry = CorrelationRuleRegistry()
    registry.register(PublicSensitiveServiceContextRule(asset_service, condition_service))
    registry.register(MultipleSecurityConditionsOnAssetRule(condition_service))
    return registry


async def _build_public_ssh_host(asset_service, org_id: str, suffix: str) -> tuple[str, str]:
    """Builds a HOST with a public IP assigned and an SSH service
    exposed — the exact canonical fact shape RULE 1 requires."""
    ip = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.IP_ADDRESS,
        scheme=IdentityScheme.IP_ADDRESS, raw_external_id=f"93.184.216.{suffix}",
        name=f"93.184.216.{suffix}", description="", discovery_source=AssetDiscoverySource.API_SCAN,
    )
    host = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.HOST,
        scheme=IdentityScheme.DISCOVERY_HOST,
        raw_external_id=f"{EntityId.generate()}:host-{suffix}",
        name=f"host-{suffix}", description="", discovery_source=AssetDiscoverySource.API_SCAN,
    )
    service = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.SERVICE,
        scheme=IdentityScheme.SERVICE_ENDPOINT, raw_external_id=f"{host.id}:tcp:22",
        name=f"ssh on host-{suffix}", description="",
        discovery_source=AssetDiscoverySource.API_SCAN,
    )
    await asset_service.add_relationship_for_org(
        org_id, ip.id, host.id, AssetRelationshipType.IP_ASSIGNED_TO_HOST,
    )
    await asset_service.add_relationship_for_org(
        org_id, host.id, service.id, AssetRelationshipType.HOST_EXPOSES_SERVICE,
    )
    return host.id, service.id


async def _ingest_sensitive_service_condition(condition_service, org_id: str, service_id: str):
    return await condition_service.ingest(
        SecurityConditionInput(
            organization_id=org_id, affected_asset_id=service_id,
            source_category="network_discovery", stable_rule_id="SENSITIVE_SERVICE_OBSERVED",
            evidence_state="observed", severity="medium",
            title="Sensitive service observed", summary="SSH observed.",
        )
    )


async def test_public_sensitive_service_context_fires_on_real_facts(factory) -> None:
    asset_service = TenantAssetService(factory)
    condition_service = TenantSecurityConditionService(factory)
    correlation_service = TenantSecurityCorrelationService(
        factory, _registry(asset_service, condition_service),
    )
    org_id = str(EntityId.generate())

    host_id, service_id = await _build_public_ssh_host(asset_service, org_id, "1")
    await _ingest_sensitive_service_condition(condition_service, org_id, service_id)

    summary = await correlation_service.evaluate(org_id)
    assert summary.matched >= 1
    assert summary.created >= 1

    correlations = await correlation_service.list_for_org(org_id, lifecycle="active")
    rule1 = [c for c in correlations if c.stable_rule_id == "PUBLIC_SENSITIVE_SERVICE_CONTEXT"]
    assert len(rule1) == 1
    assert set(rule1[0].entity_ids) == {host_id, service_id}
    assert rule1[0].evidence_state == "observed"


async def test_no_public_ip_means_no_rule1_correlation(factory) -> None:
    asset_service = TenantAssetService(factory)
    condition_service = TenantSecurityConditionService(factory)
    correlation_service = TenantSecurityCorrelationService(
        factory, _registry(asset_service, condition_service),
    )
    org_id = str(EntityId.generate())

    host = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.HOST,
        scheme=IdentityScheme.DISCOVERY_HOST, raw_external_id=f"{EntityId.generate()}:private-host",
        name="private-host", description="", discovery_source=AssetDiscoverySource.API_SCAN,
    )
    service = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.SERVICE,
        scheme=IdentityScheme.SERVICE_ENDPOINT, raw_external_id=f"{host.id}:tcp:22",
        name="ssh", description="", discovery_source=AssetDiscoverySource.API_SCAN,
    )
    await _ingest_sensitive_service_condition(condition_service, org_id, service.id)

    await correlation_service.evaluate(org_id)
    correlations = await correlation_service.list_for_org(org_id)
    assert [c for c in correlations if c.stable_rule_id == "PUBLIC_SENSITIVE_SERVICE_CONTEXT"] == []


async def test_repeat_evaluation_is_idempotent(factory) -> None:
    asset_service = TenantAssetService(factory)
    condition_service = TenantSecurityConditionService(factory)
    correlation_service = TenantSecurityCorrelationService(
        factory, _registry(asset_service, condition_service),
    )
    org_id = str(EntityId.generate())
    _host_id, service_id = await _build_public_ssh_host(asset_service, org_id, "2")
    await _ingest_sensitive_service_condition(condition_service, org_id, service_id)

    await correlation_service.evaluate(org_id)
    await correlation_service.evaluate(org_id)
    await correlation_service.evaluate(org_id)

    correlations = await correlation_service.list_for_org(org_id)
    rule1 = [c for c in correlations if c.stable_rule_id == "PUBLIC_SENSITIVE_SERVICE_CONTEXT"]
    assert len(rule1) == 1


async def test_multiple_conditions_on_asset_rule(factory) -> None:
    asset_service = TenantAssetService(factory)
    condition_service = TenantSecurityConditionService(factory)
    correlation_service = TenantSecurityCorrelationService(
        factory, _registry(asset_service, condition_service),
    )
    org_id = str(EntityId.generate())
    host = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.HOST,
        scheme=IdentityScheme.DISCOVERY_HOST, raw_external_id=f"{EntityId.generate()}:multi-host",
        name="multi-host", description="", discovery_source=AssetDiscoverySource.API_SCAN,
    )
    await condition_service.ingest(SecurityConditionInput(
        organization_id=org_id, affected_asset_id=host.id, source_category="network_discovery",
        stable_rule_id="SENSITIVE_SERVICE_OBSERVED", evidence_state="observed", severity="medium",
        title="Sensitive service A", summary="A",
    ))
    await condition_service.ingest(SecurityConditionInput(
        organization_id=org_id, affected_asset_id=host.id, source_category="network_discovery",
        stable_rule_id="MULTIPLE_REMOTE_ADMIN_SERVICES", evidence_state="observed", severity="high",
        title="Multiple remote admin services", summary="B",
    ))

    summary = await correlation_service.evaluate(org_id)
    assert summary.matched >= 1

    correlations = await correlation_service.list_for_org(org_id)
    rule3 = [c for c in correlations if c.stable_rule_id == "MULTIPLE_SECURITY_CONDITIONS_ON_ASSET"]
    assert len(rule3) == 1
    assert rule3[0].entity_ids == [host.id]
    assert len(rule3[0].condition_ids) == 2


async def test_single_condition_on_asset_does_not_fire_rule3(factory) -> None:
    asset_service = TenantAssetService(factory)
    condition_service = TenantSecurityConditionService(factory)
    correlation_service = TenantSecurityCorrelationService(
        factory, _registry(asset_service, condition_service),
    )
    org_id = str(EntityId.generate())
    host = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.HOST,
        scheme=IdentityScheme.DISCOVERY_HOST, raw_external_id=f"{EntityId.generate()}:single-host",
        name="single-host", description="", discovery_source=AssetDiscoverySource.API_SCAN,
    )
    await condition_service.ingest(SecurityConditionInput(
        organization_id=org_id, affected_asset_id=host.id, source_category="network_discovery",
        stable_rule_id="SENSITIVE_SERVICE_OBSERVED", evidence_state="observed", severity="medium",
        title="Sensitive service", summary="A",
    ))

    await correlation_service.evaluate(org_id)
    correlations = await correlation_service.list_for_org(org_id)
    assert [c for c in correlations if c.stable_rule_id == "MULTIPLE_SECURITY_CONDITIONS_ON_ASSET"] == []


async def test_title_change_does_not_duplicate(factory) -> None:
    """RULE 3's summary text changes every time condition count/
    categories change, but the correlation identity (org + rule +
    entity_ids) does not — verifies no duplicate row is created."""
    asset_service = TenantAssetService(factory)
    condition_service = TenantSecurityConditionService(factory)
    correlation_service = TenantSecurityCorrelationService(
        factory, _registry(asset_service, condition_service),
    )
    org_id = str(EntityId.generate())
    host = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.HOST,
        scheme=IdentityScheme.DISCOVERY_HOST, raw_external_id=f"{EntityId.generate()}:evolve-host",
        name="evolve-host", description="", discovery_source=AssetDiscoverySource.API_SCAN,
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
    await correlation_service.evaluate(org_id)
    first_ids = {
        c.id for c in await correlation_service.list_for_org(org_id)
        if c.stable_rule_id == "MULTIPLE_SECURITY_CONDITIONS_ON_ASSET"
    }

    await condition_service.ingest(SecurityConditionInput(
        organization_id=org_id, affected_asset_id=host.id, source_category="cloud_configuration",
        stable_rule_id="PUBLIC_STORAGE_CONFIGURATION", evidence_state="observed", severity="high",
        title="C", summary="C",
    ))
    await correlation_service.evaluate(org_id)
    second_ids = {
        c.id for c in await correlation_service.list_for_org(org_id)
        if c.stable_rule_id == "MULTIPLE_SECURITY_CONDITIONS_ON_ASSET"
    }
    assert first_ids == second_ids  # same canonical correlation, not a new one


async def test_stale_correlation_resolves_after_successful_evaluation(factory) -> None:
    asset_service = TenantAssetService(factory)
    condition_service = TenantSecurityConditionService(factory)
    correlation_service = TenantSecurityCorrelationService(
        factory, _registry(asset_service, condition_service),
    )
    org_id = str(EntityId.generate())
    host = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.HOST,
        scheme=IdentityScheme.DISCOVERY_HOST, raw_external_id=f"{EntityId.generate()}:resolve-host",
        name="resolve-host", description="", discovery_source=AssetDiscoverySource.API_SCAN,
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
    active = [
        c for c in await correlation_service.list_for_org(org_id, lifecycle="active")
        if c.stable_rule_id == "MULTIPLE_SECURITY_CONDITIONS_ON_ASSET"
    ]
    assert len(active) == 1
    correlation_id = active[0].id

    # Resolve one of the two source conditions — only 1 active condition
    # remains, so the rule no longer matches this asset.
    await condition_service.resolve_condition(cond_1.id, org_id)
    await correlation_service.evaluate(org_id)

    resolved = await correlation_service.get_for_org(correlation_id, org_id)
    assert resolved.lifecycle == "resolved"


async def test_reactivation_after_resolve_reuses_same_correlation(factory) -> None:
    asset_service = TenantAssetService(factory)
    condition_service = TenantSecurityConditionService(factory)
    correlation_service = TenantSecurityCorrelationService(
        factory, _registry(asset_service, condition_service),
    )
    org_id = str(EntityId.generate())
    host = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.HOST,
        scheme=IdentityScheme.DISCOVERY_HOST, raw_external_id=f"{EntityId.generate()}:reactivate-host",
        name="reactivate-host", description="", discovery_source=AssetDiscoverySource.API_SCAN,
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
    active = [
        c for c in await correlation_service.list_for_org(org_id, lifecycle="active")
        if c.stable_rule_id == "MULTIPLE_SECURITY_CONDITIONS_ON_ASSET"
    ]
    correlation_id = active[0].id

    await condition_service.resolve_condition(cond_1.id, org_id)
    await correlation_service.evaluate(org_id)
    assert (await correlation_service.get_for_org(correlation_id, org_id)).lifecycle == "resolved"

    # Re-observe the resolved condition (reactivates via ingest, per M8).
    await condition_service.ingest(SecurityConditionInput(
        organization_id=org_id, affected_asset_id=host.id, source_category="network_discovery",
        stable_rule_id="SENSITIVE_SERVICE_OBSERVED", evidence_state="observed", severity="medium",
        title="A", summary="A",
    ))
    await correlation_service.evaluate(org_id)
    reactivated = await correlation_service.get_for_org(correlation_id, org_id)
    assert reactivated.lifecycle == "active"
    assert reactivated.id == correlation_id  # same canonical correlation, not a new row


async def test_tenant_isolation_same_facts_two_orgs(factory) -> None:
    asset_service = TenantAssetService(factory)
    condition_service = TenantSecurityConditionService(factory)
    correlation_service = TenantSecurityCorrelationService(
        factory, _registry(asset_service, condition_service),
    )
    org_a, org_b = str(EntityId.generate()), str(EntityId.generate())

    async def build(org_id: str) -> None:
        host = await asset_service.resolve_asset(
            organization_id=org_id, asset_type=AssetType.HOST,
            scheme=IdentityScheme.DISCOVERY_HOST,
            raw_external_id=f"{EntityId.generate()}:tenant-host",
            name="tenant-host", description="", discovery_source=AssetDiscoverySource.API_SCAN,
        )
        await condition_service.ingest(SecurityConditionInput(
            organization_id=org_id, affected_asset_id=host.id, source_category="network_discovery",
            stable_rule_id="SENSITIVE_SERVICE_OBSERVED", evidence_state="observed",
            severity="medium", title="A", summary="A",
        ))
        await condition_service.ingest(SecurityConditionInput(
            organization_id=org_id, affected_asset_id=host.id, source_category="network_discovery",
            stable_rule_id="MULTIPLE_REMOTE_ADMIN_SERVICES", evidence_state="observed",
            severity="high", title="B", summary="B",
        ))

    await build(org_a)
    await build(org_b)
    await correlation_service.evaluate(org_a)
    await correlation_service.evaluate(org_b)

    corr_a = await correlation_service.list_for_org(org_a)
    corr_b = await correlation_service.list_for_org(org_b)
    assert len(corr_a) == 1
    assert len(corr_b) == 1
    assert corr_a[0].id != corr_b[0].id


async def test_evaluation_summary_resolved_count_sums_across_all_rules(factory) -> None:
    """Regression test: the evaluation summary's `resolved` count must
    be the SUM across every rule in the registry, never just the last
    rule evaluated. Caught live: RULE 1 (registered first) resolved 1
    correlation while RULE 3 (registered second, evaluated last)
    resolved 0 — the summary incorrectly reported 0 until fixed."""
    asset_service = TenantAssetService(factory)
    condition_service = TenantSecurityConditionService(factory)
    correlation_service = TenantSecurityCorrelationService(
        factory, _registry(asset_service, condition_service),
    )
    org_id = str(EntityId.generate())

    # RULE 1 fact shape: public IP + host + sensitive service.
    _host_id, service_id = await _build_public_ssh_host(asset_service, org_id, "9")
    cond_1 = await _ingest_sensitive_service_condition(condition_service, org_id, service_id)
    await correlation_service.evaluate(org_id)
    rule1_active = [
        c for c in await correlation_service.list_for_org(org_id, lifecycle="active")
        if c.stable_rule_id == "PUBLIC_SENSITIVE_SERVICE_CONTEXT"
    ]
    assert len(rule1_active) == 1

    # Resolve the only source condition — RULE 1's correlation goes
    # stale on the NEXT evaluation, while RULE 3 (evaluated after RULE
    # 1 in registry order) has nothing to resolve.
    await condition_service.resolve_condition(cond_1.id, org_id)
    summary = await correlation_service.evaluate(org_id)

    assert summary.resolved == 1
    resolved_correlation = await correlation_service.get_for_org(rule1_active[0].id, org_id)
    assert resolved_correlation.lifecycle == "resolved"
