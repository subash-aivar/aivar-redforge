"""API smoke tests for /ml-pipeline."""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from ml_pipeline.api.dependencies import reset_container
from ml_pipeline.api.v1 import router


@pytest.fixture
def app() -> FastAPI:
    reset_container()
    application = FastAPI()
    application.include_router(router)
    return application


@pytest.mark.asyncio
async def test_health(app: FastAPI) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/ml-pipeline/health")
    assert resp.status_code == 200
    assert resp.json()["context"] == "ml_pipeline"


@pytest.mark.asyncio
async def test_train_promote_requires_admin(app: FastAPI) -> None:
    tenant = str(uuid4())
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        forbidden = await client.post(
            "/ml-pipeline/models/train",
            json={"model_type": "RISK_PREDICTOR"},
            headers={"X-Tenant-Id": tenant, "X-Analytics-Roles": "analytics:viewer"},
        )
        assert forbidden.status_code == 403

        trained = await client.post(
            "/ml-pipeline/models/train",
            json={"model_type": "RISK_PREDICTOR"},
            headers={"X-Tenant-Id": tenant, "X-Analytics-Roles": "analytics:admin"},
        )
        assert trained.status_code == 200
        body = trained.json()
        assert body["status"] == "TRAINED"
        model_id = body["model_id"]

        promoted = await client.post(
            f"/ml-pipeline/models/{model_id}/promote",
            json={"deployed_by": "admin"},
            headers={"X-Tenant-Id": tenant, "X-Analytics-Roles": "analytics:admin"},
        )
        assert promoted.status_code == 200
        assert promoted.json()["status"] == "DEPLOYED"
