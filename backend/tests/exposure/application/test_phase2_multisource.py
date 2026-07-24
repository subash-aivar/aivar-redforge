from __future__ import annotations

from uuid import uuid4

import pytest

from exposure.application.commands.exposure_commands import (
    IngestAISystemRiskSignalCommand,
    IngestCloudSecuritySignalCommand,
    IngestDetectionGapSignalCommand,
    IngestVulnerabilitySignalCommand,
    RemediateCloudSecuritySignalCommand,
)
from exposure.domain.value_objects.identifiers import TenantId
from exposure.infrastructure.container import ExposureContainer
from tests.exposure.conftest import VIEWER


@pytest.mark.asyncio
async def test_cloud_security_standalone_and_amp_on_vuln(
    container: ExposureContainer, tenant_id: TenantId
) -> None:
    asset = uuid4()
    await container.ingestion.ingest_vulnerability(
        IngestVulnerabilitySignalCommand(
            tenant_id=tenant_id,
            event_id="p2-1",
            vulnerability_instance_id="vuln-p2",
            asset_ref_id=asset,
            cvss_base=5.0,
            is_kev=False,
            technique_refs=("T1190",),
        )
    )
    cloud = await container.ingestion.ingest_cloud_security(
        IngestCloudSecuritySignalCommand(
            tenant_id=tenant_id,
            event_id="p2-2",
            misconfiguration_id="misconfig-1",
            asset_ref_id=asset,
            severity_score=6.0,
            has_internet_exposure=True,
        )
    )
    assert cloud is not None
    assert cloud.signal_domain == "CloudSecurity"
    assert any(a.type == "InternetExposure" for a in cloud.amplifiers)

    vulns = await container.exposure_service.list_by_asset(
        tenant_id, asset, VIEWER, status_filter="Active"
    )
    vuln = next(v for v in vulns if v.signal_domain == "VulnerabilityManagement")
    assert any(a.type == "CloudMisconfiguration" for a in vuln.amplifiers)

    await container.ingestion.remediate_cloud_security(
        RemediateCloudSecuritySignalCommand(
            tenant_id=tenant_id,
            event_id="p2-3",
            misconfiguration_id="misconfig-1",
        )
    )


@pytest.mark.asyncio
async def test_detection_gap_is_amplifier_only(
    container: ExposureContainer, tenant_id: TenantId
) -> None:
    asset = uuid4()
    await container.ingestion.ingest_vulnerability(
        IngestVulnerabilitySignalCommand(
            tenant_id=tenant_id,
            event_id="p2-4",
            vulnerability_instance_id="vuln-gap",
            asset_ref_id=asset,
            cvss_base=4.0,
            is_kev=False,
            technique_refs=("T1059",),
        )
    )
    attached = await container.ingestion.ingest_detection_gap(
        IngestDetectionGapSignalCommand(
            tenant_id=tenant_id,
            event_id="p2-5",
            gap_id="gap-1",
            technique_ref="T1059",
            asset_ref_id=asset,
            is_open=True,
        )
    )
    assert attached >= 1
    records = await container.exposure_service.list_by_asset(tenant_id, asset, VIEWER)
    assert all(r.signal_domain != "DetectionGap" for r in records)
    assert any(a.type == "DetectionGap" for r in records for a in r.amplifiers if a.is_active)


@pytest.mark.asyncio
async def test_ai_system_risk_amplifier(container: ExposureContainer, tenant_id: TenantId) -> None:
    asset = uuid4()
    await container.ingestion.ingest_vulnerability(
        IngestVulnerabilitySignalCommand(
            tenant_id=tenant_id,
            event_id="p2-6",
            vulnerability_instance_id="vuln-ai",
            asset_ref_id=asset,
            cvss_base=3.0,
            is_kev=False,
            technique_refs=(),
        )
    )
    attached = await container.ingestion.ingest_ai_system_risk(
        IngestAISystemRiskSignalCommand(
            tenant_id=tenant_id,
            event_id="p2-7",
            asset_ref_id=asset,
            exposure_level=8.0,
            amplifier_weight=0.5,
            profile_ref="profile-1",
        )
    )
    assert attached == 1
    await container.score_worker.run_pipeline_once(
        container.debouncer, container.dispatcher, debounce_seconds=0
    )
    score = await container.exposure_service.get_latest_score(tenant_id, asset, VIEWER)
    assert score is not None
    # 3 * (1+0.5) = 4.5
    assert score.composite_score == 4.5


@pytest.mark.asyncio
async def test_multi_amplifier_score(container: ExposureContainer, tenant_id: TenantId) -> None:
    asset = uuid4()
    await container.ingestion.ingest_vulnerability(
        IngestVulnerabilitySignalCommand(
            tenant_id=tenant_id,
            event_id="p2-8",
            vulnerability_instance_id="vuln-multi",
            asset_ref_id=asset,
            cvss_base=2.0,
            is_kev=True,
            technique_refs=("T1059",),
        )
    )
    await container.ingestion.ingest_detection_gap(
        IngestDetectionGapSignalCommand(
            tenant_id=tenant_id,
            event_id="p2-9",
            gap_id="gap-2",
            technique_ref="T1059",
            asset_ref_id=asset,
            is_open=True,
        )
    )
    await container.ingestion.ingest_ai_system_risk(
        IngestAISystemRiskSignalCommand(
            tenant_id=tenant_id,
            event_id="p2-10",
            asset_ref_id=asset,
            exposure_level=5.0,
            amplifier_weight=0.5,
            profile_ref="p2",
        )
    )
    await container.score_worker.run_pipeline_once(
        container.debouncer, container.dispatcher, debounce_seconds=0
    )
    score = await container.exposure_service.get_latest_score(tenant_id, asset, VIEWER)
    assert score is not None
    # 2 * (1+1 KEV) * (1+0.5 gap) * (1+0.5 ai) = 2*2*1.5*1.5 = 9.0
    assert score.composite_score == 9.0
