from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI, Header
from httpx import ASGITransport, AsyncClient

from posture_forecasting.api.v1.routes import router
from posture_forecasting.infrastructure.container import PostureForecastingContainer
from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import MembershipRole, Permission
from redforge.shared.identifiers import EntityId


def _override_tenant_context(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
) -> TenantContext:
    return TenantContext(
        user_id=str(uuid4()),
        email="posture-forecasting-test@example.com",
        organization_id=x_tenant_id,
        role=MembershipRole.OWNER,
        permissions=frozenset(Permission),
    )


@pytest.mark.asyncio
async def test_forecast_api() -> None:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_tenant_context] = _override_tenant_context
    app.state.posture_forecasting_container = PostureForecastingContainer()
    headers = {"X-Tenant-Id": str(EntityId.generate()), "X-Roles": "ai:operator"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/posture-forecasting/forecasts",
            json={"baseline_exposure_score": 70.0},
            headers=headers,
        )
        assert r.status_code == 201
