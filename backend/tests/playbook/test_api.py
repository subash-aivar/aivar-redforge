from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI, Header
from httpx import ASGITransport, AsyncClient

from playbook.api.v1.routes import router
from playbook.infrastructure.container import PlaybookContainer
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
        email="playbook-test@example.com",
        organization_id=x_tenant_id,
        role=MembershipRole.OWNER,
        permissions=frozenset(Permission),
    )


@pytest.fixture
def app() -> FastAPI:
    application = FastAPI()
    application.include_router(router)
    application.state.playbook_container = PlaybookContainer()
    application.dependency_overrides[get_tenant_context] = _override_tenant_context
    return application


@pytest.mark.asyncio
async def test_create_and_list(app: FastAPI) -> None:
    tenant = str(uuid4())
    headers = {
        "X-Tenant-Id": tenant,
        "X-Roles": "playbook:engineer,playbook:analyst",
    }
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/playbooks",
            json={"name": "n", "description": "d", "created_by": "e"},
            headers=headers,
        )
        assert r.status_code == 201
        lst = await client.get("/playbooks", headers=headers)
        assert lst.status_code == 200
        assert len(lst.json()) == 1
