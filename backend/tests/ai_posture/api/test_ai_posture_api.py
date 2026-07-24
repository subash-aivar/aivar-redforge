"""API tests for ai_posture Phase 1 + Phase 2 endpoints."""

from __future__ import annotations

from collections.abc import Iterator
from uuid import uuid4

import pytest
from fastapi import FastAPI, Header
from httpx import ASGITransport, AsyncClient

from ai_posture.api.dependencies import get_container, reset_container
from ai_posture.api.v1.routes import router
from ai_posture.infrastructure.acl.degraded_adapters import (
    StubCloudDiscoveryQueryAdapter,
    StubDetectionRuleQueryAdapter,
    StubInventoryQueryAdapter,
)
from ai_posture.infrastructure.container import AIPostureContainer
from ai_posture.infrastructure.persistence.in_memory_unit_of_work import (
    InMemoryUnitOfWork,
)
from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import MembershipRole, Permission
from redforge.shared.identifiers import EntityId


def _override_tenant_context(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
) -> TenantContext:
    """Test-only stand-in for JWT verification: mints a TenantContext for
    whatever X-Tenant-Id the test sends, since these tests exercise
    role-based authorization (X-AI-Posture-Roles) without a full login flow.
    """
    return TenantContext(
        user_id=str(uuid4()),
        email="ai-posture-test@example.com",
        organization_id=x_tenant_id,
        role=MembershipRole.OWNER,
        permissions=frozenset(Permission),
    )


@pytest.fixture
def api_setup() -> Iterator[tuple[FastAPI, StubInventoryQueryAdapter, AIPostureContainer]]:
    reset_container()
    uow = InMemoryUnitOfWork()
    inventory = StubInventoryQueryAdapter()
    container = AIPostureContainer(
        uow_factory=lambda: uow,
        inventory_port=inventory,
        cloud_port=StubCloudDiscoveryQueryAdapter(),
        detection_port=StubDetectionRuleQueryAdapter(),
    )
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_container] = lambda: container
    app.dependency_overrides[get_tenant_context] = _override_tenant_context
    yield app, inventory, container
    reset_container()
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_register_and_get_asset(
    api_setup: tuple[FastAPI, StubInventoryQueryAdapter, AIPostureContainer],
) -> None:
    app, inventory, _ = api_setup
    tenant = str(EntityId.generate())
    asset_ref = uuid4()
    inventory.seed(asset_ref, tenant)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post(
            "/api/v1/ai-posture/assets",
            json={
                "asset_ref_id": str(asset_ref),
                "discovery_source": "ManualRegistration",
            },
            headers={
                "X-Tenant-Id": tenant,
                "X-AI-Posture-Roles": "ai_posture:engineer",
            },
        )
        assert resp.status_code == 200, resp.text
        asset_id = resp.json()["asset_id"]
        get_resp = await ac.get(
            f"/api/v1/ai-posture/assets/{asset_id}",
            headers={"X-Tenant-Id": tenant},
        )
        assert get_resp.status_code == 200
        assert get_resp.json()["asset_id"] == asset_id


@pytest.mark.asyncio
async def test_forbidden_without_engineer(
    api_setup: tuple[FastAPI, StubInventoryQueryAdapter, AIPostureContainer],
) -> None:
    app, inventory, _ = api_setup
    tenant = str(EntityId.generate())
    asset_ref = uuid4()
    inventory.seed(asset_ref, tenant)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post(
            "/api/v1/ai-posture/assets",
            json={"asset_ref_id": str(asset_ref)},
            headers={
                "X-Tenant-Id": tenant,
                "X-AI-Posture-Roles": "ai_posture:reader",
            },
        )
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_shadow_alert_bulk_triage_api(
    api_setup: tuple[FastAPI, StubInventoryQueryAdapter, AIPostureContainer],
) -> None:
    app, _, _ = api_setup
    tenant = str(EntityId.generate())
    headers = {
        "X-Tenant-Id": tenant,
        "X-AI-Posture-Roles": "ai_posture:engineer",
    }
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        for i in range(2):
            r = await ac.post(
                "/api/v1/ai-posture/shadow-alerts",
                json={
                    "cloud_account": "acct",
                    "resource_identifier": f"api-{i}",
                    "service_type": "openai",
                    "region": "us-east-1",
                    "discovery_source": "ManualRegistration",
                },
                headers=headers,
            )
            assert r.status_code == 200
        triage = await ac.post(
            "/api/v1/ai-posture/shadow-alerts/bulk-triage",
            json={"triaged_by": "analyst", "service_type": "openai"},
            headers={
                "X-Tenant-Id": tenant,
                "X-AI-Posture-Roles": "ai_posture:analyst",
            },
        )
        assert triage.status_code == 200
        assert triage.json()["triaged_count"] == 2


@pytest.mark.asyncio
async def test_threat_profile_and_risk_score_api(
    api_setup: tuple[FastAPI, StubInventoryQueryAdapter, AIPostureContainer],
) -> None:
    app, inventory, _ = api_setup
    tenant = str(EntityId.generate())
    asset_ref = uuid4()
    inventory.seed(asset_ref, tenant)
    headers_eng = {
        "X-Tenant-Id": tenant,
        "X-AI-Posture-Roles": "ai_posture:engineer",
    }
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        reg = await ac.post(
            "/api/v1/ai-posture/assets",
            json={
                "asset_ref_id": str(asset_ref),
                "discovery_source": "ManualRegistration",
            },
            headers=headers_eng,
        )
        asset_id = reg.json()["asset_id"]
        await ac.post(
            f"/api/v1/ai-posture/assets/{asset_id}/classify",
            json={"ai_system_kind": "FoundationModelAPI"},
            headers=headers_eng,
        )
        tp = await ac.post(
            f"/api/v1/ai-posture/assets/{asset_id}/threat-profile",
            headers=headers_eng,
        )
        assert tp.status_code == 200
        assess = await ac.post(
            f"/api/v1/ai-posture/assets/{asset_id}/threat-profile/assess",
            json={"evidence_refs": ["e1"]},
            headers=headers_eng,
        )
        assert assess.status_code == 200
        # GET must not compute
        empty = await ac.get(
            f"/api/v1/ai-posture/assets/{asset_id}/risk-score",
            headers={"X-Tenant-Id": tenant},
        )
        assert empty.status_code == 200
        assert empty.json() is None
        compute = await ac.post(
            f"/api/v1/ai-posture/assets/{asset_id}/risk-score/compute",
            headers=headers_eng,
        )
        assert compute.status_code == 200
        assert "composite_score" in compute.json()
