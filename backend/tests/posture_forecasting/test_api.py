from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from posture_forecasting.api.v1.routes import router
from posture_forecasting.infrastructure.container import PostureForecastingContainer


@pytest.mark.asyncio
async def test_forecast_api() -> None:
    app = FastAPI()
    app.include_router(router)
    app.state.posture_forecasting_container = PostureForecastingContainer()
    headers = {"X-Tenant-Id": str(uuid4()), "X-Roles": "ai:operator"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/posture-forecasting/forecasts",
            json={"baseline_exposure_score": 70.0},
            headers=headers,
        )
        assert r.status_code == 201
