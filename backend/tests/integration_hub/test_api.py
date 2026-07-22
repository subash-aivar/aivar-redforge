from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI, Header
from httpx import ASGITransport, AsyncClient

from integration_hub.api.v1.routes import router
from integration_hub.infrastructure.container import IntegrationHubContainer
from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import MembershipRole, Permission


def _override_tenant_context(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
) -> TenantContext:
    """Test-only stand-in for JWT verification: mints a TenantContext for
    whatever X-Tenant-Id the test sends, since these tests exercise
    role-based authorization (X-Roles) without a full login flow.
    """
    return TenantContext(
        user_id=str(uuid4()),
        email="integration-hub-test@example.com",
        organization_id=x_tenant_id,
        role=MembershipRole.OWNER,
        permissions=frozenset(Permission),
    )


@pytest.mark.asyncio
async def test_register_list() -> None:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_tenant_context] = _override_tenant_context
    app.state.integration_hub_container = IntegrationHubContainer()
    headers = {"X-Tenant-Id": str(uuid4()), "X-Roles": "integration:admin"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/integration-hub/connectors",
            json={
                "connector_type": "ITSM_JIRA",
                "display_name": "jira",
                "credential_vault_key": "v/jira",
                "credential_type": "API_KEY",
            },
            headers=headers,
        )
        assert r.status_code == 201
        lst = await client.get("/integration-hub/connectors", headers=headers)
        assert len(lst.json()) == 1
