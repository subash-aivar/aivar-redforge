from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI, Header
from httpx import ASGITransport, AsyncClient

from autonomous_intelligence.api.v1.routes import router
from autonomous_intelligence.infrastructure.container import AutonomousIntelligenceContainer
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
        email="autonomous-intelligence-test@example.com",
        organization_id=x_tenant_id,
        role=MembershipRole.OWNER,
        permissions=frozenset(Permission),
    )


@pytest.mark.asyncio
async def test_create_and_queue() -> None:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_tenant_context] = _override_tenant_context
    app.state.autonomous_intelligence_container = AutonomousIntelligenceContainer()
    headers = {"X-Tenant-Id": str(EntityId.generate()), "X-Roles": "system,soc:detection_engineer"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/autonomous-intelligence/suggestions",
            json={
                "target_context": "detection",
                "target_type": "detection_rule_tuning",
                "confidence_score": 0.9,
                "rationale_summary": "raise threshold",
            },
            headers=headers,
        )
        assert r.status_code == 201
        q = await client.get("/autonomous-intelligence/suggestions", headers=headers)
        assert q.status_code == 200
        assert len(q.json()) == 1
