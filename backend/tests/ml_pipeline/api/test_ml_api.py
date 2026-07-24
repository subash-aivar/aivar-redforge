"""API smoke tests for /ml-pipeline."""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI, Header
from httpx import ASGITransport, AsyncClient

from ml_pipeline.api.dependencies import reset_container
from ml_pipeline.api.v1 import router
from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import MembershipRole, Permission
from redforge.shared.identifiers import EntityId


def _override_tenant_context(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
) -> TenantContext:
    """Test-only stand-in for JWT verification: mints a TenantContext for
    whatever X-Tenant-Id the test sends, since these tests exercise
    role-based authorization (X-Analytics-Roles) without a full login flow.
    """
    return TenantContext(
        user_id=str(uuid4()),
        email="ml-pipeline-test@example.com",
        organization_id=x_tenant_id,
        role=MembershipRole.OWNER,
        permissions=frozenset(Permission),
    )


@pytest.fixture
def app() -> FastAPI:
    reset_container()
    application = FastAPI()
    application.include_router(router)
    application.dependency_overrides[get_tenant_context] = _override_tenant_context
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
    tenant = str(EntityId.generate())
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
