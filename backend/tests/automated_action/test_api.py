from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI, Header
from httpx import ASGITransport, AsyncClient

from automated_action.api.v1.routes import router
from automated_action.application.ports.lookups import PlaybookLookupView, PlaybookStepView
from automated_action.infrastructure.container import AutomatedActionContainer
from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import MembershipRole, Permission
from redforge.shared.identifiers import EntityId


def _override_tenant_context(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
) -> TenantContext:
    """Test-only stand-in for JWT verification: mints a TenantContext for
    whatever X-Tenant-Id the test sends, since these tests exercise
    role-based authorization (X-Roles) without a full login flow.
    """
    return TenantContext(
        user_id=str(uuid4()),
        email="automated-action-test@example.com",
        organization_id=x_tenant_id,
        role=MembershipRole.OWNER,
        permissions=frozenset(Permission),
    )


@pytest.mark.asyncio
async def test_trigger_api() -> None:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_tenant_context] = _override_tenant_context
    c = AutomatedActionContainer()
    pb = uuid4()
    c.playbook_lookup.put(
        PlaybookLookupView(
            str(pb),
            1,
            "h",
            "LOW",
            "APPROVED",
            [PlaybookStepView(1, "a", "COMM_SLACK", "c", {}, "LOW")],
        )
    )
    app.state.automated_action_container = c
    headers = {"X-Tenant-Id": str(EntityId.generate()), "X-Roles": "automation:operator"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/executions",
            json={
                "playbook_id": str(pb),
                "version_number": 1,
                "source_event_id": "e1",
            },
            headers=headers,
        )
        assert r.status_code == 201
