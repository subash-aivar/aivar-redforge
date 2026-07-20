"""Correlation + ACL adapter tests — Phase 4."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from detection.domain.ports.correlation_ports import AssetMetadataSnapshot
from detection.domain.services.correlation import CorrelationService
from detection.domain.value_objects.enums import CorrelationStatus
from detection.infrastructure.acl.degraded_adapters import (
    BehavioralSignalAdapter,
    CloudContextAdapter,
    ComplianceAdapter,
    InventoryAdapter,
    ThreatIntelAdapter,
    VulnerabilityContextAdapter,
)
from tests.detection.phase3_helpers import make_finding
from tests.detection.phase4_helpers import make_tenant


class _BoomInventory(InventoryAdapter):
    async def resolve_asset(self, asset_id, tenant_id):
        raise RuntimeError("inventory down")


class _RichInventory(InventoryAdapter):
    async def resolve_asset(self, asset_id, tenant_id):
        return AssetMetadataSnapshot(
            asset_id=asset_id, asset_type="server", business_criticality=0.9
        )


def _svc(**overrides):
    kwargs = dict(
        inventory=InventoryAdapter(),
        cloud=CloudContextAdapter(),
        vulnerability=VulnerabilityContextAdapter(),
        threat_intel=ThreatIntelAdapter(),
        compliance=ComplianceAdapter(),
        behavioral=BehavioralSignalAdapter(),
    )
    kwargs.update(overrides)
    return CorrelationService(**kwargs)


@pytest.mark.asyncio
async def test_correlation_completed_degraded() -> None:
    finding = make_finding(tenant_id=make_tenant(), now=datetime.now(UTC))
    result = await _svc().correlate(finding, finding.tenant_id, now=datetime.now(UTC))
    assert result.status == CorrelationStatus.COMPLETED
    assert result.correlation.enriched is True
    assert result.sources_succeeded == 6


@pytest.mark.asyncio
async def test_correlation_partial_on_adapter_failure() -> None:
    finding = make_finding(tenant_id=make_tenant(), now=datetime.now(UTC))
    result = await _svc(inventory=_BoomInventory()).correlate(
        finding, finding.tenant_id, now=datetime.now(UTC)
    )
    assert result.status == CorrelationStatus.PARTIAL
    assert result.sources_failed == 1
    assert result.sources_succeeded == 5


@pytest.mark.asyncio
async def test_correlation_asset_metadata() -> None:
    finding = make_finding(tenant_id=make_tenant(), now=datetime.now(UTC))
    result = await _svc(inventory=_RichInventory()).correlate(
        finding, finding.tenant_id, now=datetime.now(UTC)
    )
    assert result.correlation.context.asset_metadata["asset_type"] == "server"


@pytest.mark.asyncio
@pytest.mark.parametrize("i", range(40))
async def test_degraded_adapters_stable(i: int) -> None:
    tid = make_tenant()
    asset = f"asset-{i}"
    inv = await InventoryAdapter().resolve_asset(asset, tid)
    cloud = await CloudContextAdapter().resolve_cloud(asset, tid)
    vulns = await VulnerabilityContextAdapter().resolve_vulnerabilities(asset, tid)
    threats = await ThreatIntelAdapter().resolve_threat_actors(
        asset_id=asset, rule_id=str(uuid4()), tenant_id=tid
    )
    controls = await ComplianceAdapter().resolve_controls(str(uuid4()), tid)
    behav = await BehavioralSignalAdapter().resolve_behavioral(asset, tid)
    assert inv.asset_id == asset
    assert cloud.internet_exposed is False
    assert vulns == []
    assert threats == []
    assert controls == []
    assert behav.anomaly_score == 0.0


@pytest.mark.asyncio
async def test_sibling_refs_passed() -> None:
    finding = make_finding(tenant_id=make_tenant(), now=datetime.now(UTC))
    sib = (str(uuid4()),)
    result = await _svc().correlate(
        finding, finding.tenant_id, sibling_finding_refs=sib, now=datetime.now(UTC)
    )
    assert result.correlation.context.sibling_finding_refs == sib
