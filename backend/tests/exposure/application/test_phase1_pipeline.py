from __future__ import annotations

from uuid import uuid4

import pytest

from exposure.application.commands.exposure_commands import (
    ConfigureAmplifierWeightsCommand,
    IngestVulnerabilitySignalCommand,
    ResolveVulnerabilitySignalCommand,
    SuppressExposureRecordCommand,
    VulnerabilityKevStatusChangedCommand,
)
from exposure.domain.value_objects.identifiers import TenantId
from exposure.infrastructure.container import ExposureContainer
from tests.exposure.conftest import ADMIN, ANALYST, VIEWER


@pytest.mark.asyncio
async def test_ingest_debounce_compute_end_to_end(
    container: ExposureContainer, tenant_id: TenantId
) -> None:
    asset = uuid4()
    dto = await container.ingestion.ingest_vulnerability(
        IngestVulnerabilitySignalCommand(
            tenant_id=tenant_id,
            event_id="e1",
            vulnerability_instance_id="vuln-a",
            asset_ref_id=asset,
            cvss_base=7.0,
            is_kev=True,
            technique_refs=("T1059",),
        )
    )
    assert dto is not None
    assert dto.status == "Active"
    assert any(a.type == "KevPresent" for a in dto.amplifiers)

    # thundering herd: many marks → one pending row
    for _ in range(100):
        await container.debouncer.mark(tenant_id, asset)
    assert await container._uow_factory().pending.count_for_tenant(tenant_id) == 1

    computed = await container.score_worker.run_pipeline_once(
        container.debouncer, container.dispatcher, debounce_seconds=0
    )
    assert computed == 1
    score = await container.exposure_service.get_latest_score(tenant_id, asset, VIEWER)
    assert score is not None
    assert score.composite_score == 10.0  # 7 * (1+1) clamped


@pytest.mark.asyncio
async def test_idempotent_event_replay(container: ExposureContainer, tenant_id: TenantId) -> None:
    asset = uuid4()
    cmd = IngestVulnerabilitySignalCommand(
        tenant_id=tenant_id,
        event_id="dup-1",
        vulnerability_instance_id="vuln-b",
        asset_ref_id=asset,
        cvss_base=4.0,
        is_kev=False,
        technique_refs=(),
    )
    first = await container.ingestion.ingest_vulnerability(cmd)
    second = await container.ingestion.ingest_vulnerability(cmd)
    assert first is not None
    assert second is None


@pytest.mark.asyncio
async def test_resolve_and_suppress_auth(container: ExposureContainer, tenant_id: TenantId) -> None:
    asset = uuid4()
    dto = await container.ingestion.ingest_vulnerability(
        IngestVulnerabilitySignalCommand(
            tenant_id=tenant_id,
            event_id="e2",
            vulnerability_instance_id="vuln-c",
            asset_ref_id=asset,
            cvss_base=5.0,
            is_kev=False,
            technique_refs=(),
        )
    )
    assert dto is not None
    suppressed = await container.exposure_service.suppress(
        SuppressExposureRecordCommand(
            tenant_id=tenant_id,
            record_id=__import__("uuid").UUID(dto.record_id),
            justification="accepted risk",
            suppressed_by="analyst-1",
            actor_roles=ANALYST,
        )
    )
    assert suppressed.status == "Suppressed"

    await container.ingestion.resolve_vulnerability(
        ResolveVulnerabilitySignalCommand(
            tenant_id=tenant_id,
            event_id="e3",
            vulnerability_instance_id="vuln-d",
        )
    )


@pytest.mark.asyncio
async def test_weight_change_triggers_pending(
    container: ExposureContainer, tenant_id: TenantId
) -> None:
    asset = uuid4()
    await container.ingestion.ingest_vulnerability(
        IngestVulnerabilitySignalCommand(
            tenant_id=tenant_id,
            event_id="e4",
            vulnerability_instance_id="vuln-e",
            asset_ref_id=asset,
            cvss_base=3.0,
            is_kev=True,
            technique_refs=(),
        )
    )
    cfg = await container.exposure_service.configure_weights(
        ConfigureAmplifierWeightsCommand(
            tenant_id=tenant_id,
            weights={"KevPresent": 0.5},
            change_rationale="tune kev",
            changed_by="admin",
            actor_roles=ADMIN,
        )
    )
    assert cfg.version == 2
    assert await container._uow_factory().pending.count_for_tenant(tenant_id) >= 1


@pytest.mark.asyncio
async def test_kev_status_toggle(container: ExposureContainer, tenant_id: TenantId) -> None:
    asset = uuid4()
    await container.ingestion.ingest_vulnerability(
        IngestVulnerabilitySignalCommand(
            tenant_id=tenant_id,
            event_id="e5",
            vulnerability_instance_id="vuln-f",
            asset_ref_id=asset,
            cvss_base=6.0,
            is_kev=False,
            technique_refs=(),
        )
    )
    dto = await container.ingestion.kev_status_changed(
        VulnerabilityKevStatusChangedCommand(
            tenant_id=tenant_id,
            event_id="e6",
            vulnerability_instance_id="vuln-f",
            is_kev=True,
        )
    )
    assert dto is not None
    assert any(a.type == "KevPresent" and a.is_active for a in dto.amplifiers)
