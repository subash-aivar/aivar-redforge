from __future__ import annotations

from collections.abc import Iterator
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from exposure.api.dependencies import get_container, reset_container
from exposure.api.v1.routes import router
from exposure.infrastructure.container import ExposureContainer
from exposure.infrastructure.persistence.in_memory_unit_of_work import (
    InMemoryUnitOfWork,
)


@pytest.fixture
def api_setup() -> Iterator[tuple[FastAPI, ExposureContainer]]:
    reset_container()
    uow = InMemoryUnitOfWork()
    container = ExposureContainer(uow_factory=lambda: uow)
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_container] = lambda: container
    yield app, container
    reset_container()
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_api_ingest_get_suppress_score(
    api_setup: tuple[FastAPI, ExposureContainer],
) -> None:
    app, _ = api_setup
    tenant = str(uuid4())
    asset = uuid4()
    headers = {"X-Tenant-Id": tenant, "X-Exposure-Roles": "exposure:analyst"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post(
            "/api/v1/exposure/internal/signals/vulnerability",
            json={
                "event_id": "api-1",
                "vulnerability_instance_id": "v-api",
                "asset_ref_id": str(asset),
                "cvss_base": 5.0,
                "is_kev": True,
                "technique_refs": [],
            },
            headers=headers,
        )
        assert resp.status_code == 200, resp.text
        record_id = resp.json()["record_id"]
        get_resp = await ac.get(
            f"/api/v1/exposure/records/{record_id}",
            headers={"X-Tenant-Id": tenant, "X-Exposure-Roles": "exposure:viewer"},
        )
        assert get_resp.status_code == 200
        forbid = await ac.put(
            "/api/v1/exposure/weights",
            json={
                "weights": {"KevPresent": 0.2},
                "change_rationale": "nope",
                "changed_by": "x",
            },
            headers={"X-Tenant-Id": tenant, "X-Exposure-Roles": "exposure:viewer"},
        )
        assert forbid.status_code == 403
        pipe = await ac.post(
            "/api/v1/exposure/admin/pipeline/run",
            headers={"X-Tenant-Id": tenant, "X-Exposure-Roles": "exposure:admin"},
        )
        assert pipe.status_code == 200
        score = await ac.get(
            f"/api/v1/exposure/assets/{asset}/score",
            headers={"X-Tenant-Id": tenant, "X-Exposure-Roles": "exposure:viewer"},
        )
        assert score.status_code == 200
        assert score.json()["composite_score"] == 10.0


@pytest.mark.asyncio
async def test_health(api_setup: tuple[FastAPI, ExposureContainer]) -> None:
    app, _ = api_setup
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/v1/exposure/health")
    assert resp.status_code == 200
    assert resp.json()["context"] == "exposure"
