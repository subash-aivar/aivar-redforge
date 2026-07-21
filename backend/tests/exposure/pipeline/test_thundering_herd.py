from __future__ import annotations

from uuid import uuid4

import pytest

from exposure.application.commands.exposure_commands import IngestVulnerabilitySignalCommand
from exposure.domain.value_objects.identifiers import TenantId
from exposure.infrastructure.container import ExposureContainer


@pytest.mark.asyncio
async def test_10k_marks_collapse_to_one_pending_and_one_compute(
    container: ExposureContainer, tenant_id: TenantId
) -> None:
    asset = uuid4()
    await container.ingestion.ingest_vulnerability(
        IngestVulnerabilitySignalCommand(
            tenant_id=tenant_id.value,
            event_id="herd-0",
            vulnerability_instance_id="vuln-herd",
            asset_ref_id=asset,
            cvss_base=5.0,
            is_kev=False,
            technique_refs=(),
        )
    )
    for _ in range(10_000):
        await container.debouncer.mark(tenant_id.value, asset)
    assert await container._uow_factory().pending.count_for_tenant(tenant_id) == 1
    computed = await container.score_worker.run_pipeline_once(
        container.debouncer, container.dispatcher, debounce_seconds=0
    )
    assert computed == 1
    # second dispatch with no new marks → 0
    computed2 = await container.score_worker.run_pipeline_once(
        container.debouncer, container.dispatcher, debounce_seconds=0
    )
    assert computed2 == 0
