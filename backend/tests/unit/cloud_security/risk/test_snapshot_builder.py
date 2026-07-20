"""Unit tests for RiskSnapshotBuilder / RiskEvidenceCollector."""

from __future__ import annotations

import pytest

from redforge.application.cloud_security.risk.snapshot_builder import (
    RiskEvidenceCollector,
    RiskSnapshotBuilder,
)
from redforge.domain.cloud_security.cloud_asset import CloudAsset
from redforge.domain.cloud_security.value_objects import OrganizationId
from redforge.infrastructure.cloud_security.acl.exposure_acl import ExposureSignalACL
from redforge.infrastructure.cloud_security.acl.threat_intel_acl import ThreatIntelRiskACL


@pytest.mark.asyncio
async def test_builder_from_asset_config(sample_asset: CloudAsset) -> None:
    builder = RiskSnapshotBuilder()
    snap = await builder.build(sample_asset)
    assert snap.network_exposure == "PUBLIC"
    assert snap.public_accessibility is True
    assert snap.encryption_at_rest is False
    assert snap.business_criticality == "HIGH"
    assert ("criticality", "high") in snap.tags


@pytest.mark.asyncio
async def test_builder_with_fake_findings(sample_asset: CloudAsset) -> None:
    async def findings(asset: CloudAsset, org: OrganizationId) -> tuple[str, ...]:
        assert org == asset.organization_id
        return ("CRITICAL", "HIGH")

    collector = RiskEvidenceCollector(finding_severities=findings)
    snap = await RiskSnapshotBuilder(collector).build(sample_asset)
    assert snap.open_finding_severities == ("CRITICAL", "HIGH")
    assert snap.compliance_gap_ratio == pytest.approx(0.2)


@pytest.mark.asyncio
async def test_builder_with_privilege_and_runtime(sample_asset: CloudAsset) -> None:
    async def privilege(asset: CloudAsset, org: OrganizationId) -> str:
        return "ADMIN"

    async def runtime(asset: CloudAsset, org: OrganizationId) -> tuple[str, ...]:
        return ("MEDIUM", "LOW")

    async def k8s(asset: CloudAsset, org: OrganizationId) -> float | None:
        return 80.0

    collector = RiskEvidenceCollector(
        privilege_level=privilege,
        runtime_severities=runtime,
        k8s_score=k8s,
    )
    snap = await RiskSnapshotBuilder(collector).build(sample_asset)
    assert snap.privilege_level == "ADMIN"
    assert snap.runtime_event_severities == ("MEDIUM", "LOW")
    assert snap.k8s_security_score == 80.0


@pytest.mark.asyncio
async def test_threat_intel_stub_returns_zero(sample_asset: CloudAsset) -> None:
    acl = ThreatIntelRiskACL()
    assert await acl.threat_intel_score_for_asset(sample_asset) == 0.0


def test_exposure_acl_from_config(sample_asset: CloudAsset) -> None:
    signals = ExposureSignalACL().from_asset(sample_asset)
    assert signals["internet_exposure"] is True
    assert signals["encryption_at_rest"] is False


@pytest.mark.asyncio
async def test_build_for_assets_map(sample_asset: CloudAsset) -> None:
    out = await RiskSnapshotBuilder().build_for_assets([sample_asset])
    assert sample_asset.id.value in out


@pytest.mark.asyncio
async def test_custom_compliance_gap_loader(sample_asset: CloudAsset) -> None:
    async def gap(asset: CloudAsset) -> float:
        return 0.55

    collector = RiskEvidenceCollector(compliance_gap_loader=gap)
    snap = await collector.collect(sample_asset)
    assert snap.compliance_gap_ratio == 0.55


@pytest.mark.asyncio
async def test_lateral_movement_metadata_only(sample_asset: CloudAsset) -> None:
    snap = await RiskSnapshotBuilder().build(sample_asset)
    assert snap.lateral_movement_potential == "UNKNOWN"
