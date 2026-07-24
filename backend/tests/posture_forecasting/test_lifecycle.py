from __future__ import annotations

import pytest

from posture_forecasting.application.commands.forecast_commands import GeneratePostureForecast
from posture_forecasting.infrastructure.container import PostureForecastingContainer
from redforge.shared.identifiers import EntityId


@pytest.mark.asyncio
async def test_generate_forecast() -> None:
    c = PostureForecastingContainer()
    tenant = EntityId.generate()
    dto = await c.app.generate(GeneratePostureForecast(tenant, 80.0, 2.0, 3, 10, ("ai:operator",)))
    assert dto.predicted_90d <= dto.predicted_30d
    latest = await c.app.get_latest(tenant, ("ai:operator",))
    assert latest.forecast_id == dto.forecast_id


@pytest.mark.asyncio
async def test_worker_tick() -> None:
    c = PostureForecastingContainer()
    await c.scheduler.tick_all(EntityId.generate())
    assert c.forecast_worker.runs == 1
