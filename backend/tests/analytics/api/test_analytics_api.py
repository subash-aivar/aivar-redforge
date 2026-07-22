from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi import FastAPI, Header
from httpx import ASGITransport, AsyncClient

from analytics.api.dependencies import reset_container
from analytics.api.v1.routes import router
from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import MembershipRole, Permission


def _override_tenant_context(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
) -> TenantContext:
    """Test-only stand-in for JWT verification: mints a TenantContext for
    whatever X-Tenant-Id the test sends, since these tests exercise
    role-based authorization (X-Analytics-Roles) without a full login flow.
    """
    return TenantContext(
        user_id=str(uuid4()),
        email="analytics-test@example.com",
        organization_id=x_tenant_id,
        role=MembershipRole.OWNER,
        permissions=frozenset(Permission),
    )


@pytest.fixture
def app() -> FastAPI:
    reset_container()
    application = FastAPI()
    application.include_router(router, prefix="/api/v1")
    application.dependency_overrides[get_tenant_context] = _override_tenant_context
    return application


@pytest.fixture
async def client(app: FastAPI):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _headers(tenant: str, roles: str = "analytics:engineer") -> dict[str, str]:
    return {"X-Tenant-Id": tenant, "X-Analytics-Roles": roles}


@pytest.mark.asyncio
async def test_register_dataset_and_summary(client: AsyncClient) -> None:
    tenant = str(uuid4())
    r = await client.post(
        "/api/v1/analytics/datasets",
        json={"domain": "Vulnerability", "schema_version": "1"},
        headers=_headers(tenant),
    )
    assert r.status_code == 200
    dataset_id = r.json()["dataset_id"]

    r2 = await client.get(
        f"/api/v1/analytics/datasets/{dataset_id}",
        headers=_headers(tenant, "analytics:viewer"),
    )
    assert r2.status_code == 200
    assert r2.json()["domain"] == "Vulnerability"

    r3 = await client.get(
        "/api/v1/analytics/summary",
        headers=_headers(tenant, "analytics:viewer"),
    )
    assert r3.status_code == 200


@pytest.mark.asyncio
async def test_viewer_cannot_define_kpi(client: AsyncClient) -> None:
    tenant = str(uuid4())
    r = await client.post(
        "/api/v1/analytics/kpis",
        json={"kpi_type": "MTTD"},
        headers=_headers(tenant, "analytics:viewer"),
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_ingest_idempotent_and_kpi_compute(client: AsyncClient) -> None:
    tenant = str(uuid4())
    now = datetime.now(UTC).isoformat()
    body = {
        "domain": "Vulnerability",
        "event_id": "evt-1",
        "event_type": "VulnerabilityInstanceDiscovered",
        "event_ts": now,
        "payload": {},
    }
    r1 = await client.post(
        "/api/v1/analytics/internal/events",
        json=body,
        headers=_headers(tenant),
    )
    assert r1.status_code == 200
    assert r1.json()["ingested"] is True
    r2 = await client.post(
        "/api/v1/analytics/internal/events",
        json=body,
        headers=_headers(tenant),
    )
    assert r2.status_code == 200
    assert r2.json()["ingested"] is False

    r3 = await client.post(
        "/api/v1/analytics/admin/kpis/compute",
        json={"kpi_type": "MTTR"},
        headers=_headers(tenant, "analytics:admin"),
    )
    assert r3.status_code == 200
    assert r3.json()["status"] == "RequiresM34Data"


@pytest.mark.asyncio
async def test_query_requires_analyst(client: AsyncClient) -> None:
    tenant = str(uuid4())
    created = await client.post(
        "/api/v1/analytics/queries",
        json={
            "name": "kpis",
            "template": ("SELECT * FROM analytics.kpi_snapshots WHERE tenant_id = :tenant_id"),
            "domain": "CrossDomain",
            "parameters": [],
        },
        headers=_headers(tenant, "analytics:engineer"),
    )
    assert created.status_code == 200
    qid = created.json()["query_id"]
    denied = await client.post(
        f"/api/v1/analytics/queries/{qid}/execute",
        json={"parameters": {}, "executed_by": "u"},
        headers=_headers(tenant, "analytics:viewer"),
    )
    assert denied.status_code == 403
