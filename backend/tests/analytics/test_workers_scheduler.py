from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from analytics.infrastructure.container import AnalyticsContainer
from redforge.shared.identifiers import EntityId


@pytest.mark.asyncio
async def test_projection_worker_and_scheduler_tick() -> None:
    c = AnalyticsContainer()
    tid = EntityId.generate()
    ingested = await c.projection_worker.handle(
        tenant_id=tid,
        domain="Vulnerability",
        event_id="w1",
        event_type="VulnerabilityInstanceDiscovered",
        event_ts=datetime.now(UTC),
        payload={"asset_ref_id": str(uuid4())},
    )
    assert ingested["ingested"] is True
    tick = await c.scheduler.daily_tick(tid)
    assert "kpi_results" in tick
    assert tick["retention"]["archived_rows"] >= 0
    assert tick["partitions"]["ok"] is True


@pytest.mark.asyncio
async def test_rebuild_worker() -> None:
    c = AnalyticsContainer()
    tid = EntityId.generate()
    from analytics.application.commands.analytics_commands import (
        RegisterAnalyticsDataSetCommand,
    )

    await c.app.register_dataset(
        RegisterAnalyticsDataSetCommand(tid, "Vulnerability", "1", ("analytics:engineer",))
    )
    await c.projection_worker.handle(
        tenant_id=tid,
        domain="Vulnerability",
        event_id="r1",
        event_type="VulnerabilityInstanceDiscovered",
        event_ts=datetime.now(UTC),
        payload={},
    )
    result = await c.rebuild_worker.run(tid, domain="Vulnerability")
    assert result["rebuilt_datasets"] >= 1
