from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI, Header
from httpx import ASGITransport, AsyncClient

from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import MembershipRole, Permission
from redforge.shared.identifiers import EntityId
from threat_hunt.api.v1.routes import router
from threat_hunt.infrastructure.container import ThreatHuntContainer


def _override_tenant_context(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
) -> TenantContext:
    return TenantContext(
        user_id=str(uuid4()),
        email="threat-hunt-test@example.com",
        organization_id=x_tenant_id,
        role=MembershipRole.OWNER,
        permissions=frozenset(Permission),
    )


@pytest.mark.asyncio
async def test_candidates_api() -> None:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_tenant_context] = _override_tenant_context
    app.state.threat_hunt_container = ThreatHuntContainer()
    headers = {"X-Tenant-Id": str(EntityId.generate()), "X-Roles": "system,soc:detection_engineer"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/threat-hunt/candidates",
            json={"anomaly_signal_ids": ["a1"], "technique_ids": ["T1059"]},
            headers=headers,
        )
        assert r.status_code == 201
        q = await client.get("/threat-hunt/candidates", headers=headers)
        assert len(q.json()) == 1
