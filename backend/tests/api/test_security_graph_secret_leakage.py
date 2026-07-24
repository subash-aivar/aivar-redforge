"""Secret-leakage sentinel proof for the M4 Security Graph — proves a
secret embedded in an asset's metadata/description never reaches the
projected graph node's `attributes`, because SecurityGraphProjector
only ever forwards a small explicit allowlist of safe fields
(asset_type, name) — never the full AIAsset aggregate or its metadata
dict.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_ai_target_service,
    get_auth_service,
    get_effective_access_service,
    get_organization_service,
    get_tenant_asset_service,
    get_tenant_security_graph_service,
    get_token_service,
    get_user_status_service,
)
from redforge.api.v1.ai_targets import router as targets_router
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.organizations import router as org_router
from redforge.api.v1.security_graph import router as security_graph_router
from redforge.application.ai_targets import AITargetService
from redforge.application.auth import AuthService
from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.organizations import OrganizationService
from redforge.application.security_graph.query_service import TenantSecurityGraphService
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware

_SENTINEL_SECRET = "sk-REDFORGE_SG_SENTINEL_MUST_NOT_LEAK_zzz999"


class _AlwaysActiveUserStatusService:
    async def get_status(self, user_id: str) -> str:
        return "active"


class _NoOpEffectiveAccessService:
    """M17 regression shim for isolated test apps that build their own
    minimal FastAPI app without a real database engine: these tests
    never configure custom RBAC roles/groups, so the additive
    effective-access lookup is a no-op and the membership is always
    treated as active (each test asserts its own suspension/removal
    behavior through the real membership endpoints, not through this
    stub)."""

    async def get_additional_permissions(self, organization_id: str, user_id: str) -> frozenset:
        return frozenset()

    async def is_membership_active(self, organization_id: str, user_id: str) -> bool:
        return True


@pytest.fixture
async def engine():
    eng = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[t for t in Base.metadata.sorted_tables if t.schema is None],
        )
    yield eng
    await eng.dispose()


@pytest.fixture
async def factory(engine):
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture
def app(factory):
    hasher = Argon2PasswordHasher(time_cost=1, memory_cost=16384, parallelism=1)
    tokens = JWTTokenService(
        secret_key="test-secret-key-that-is-long-enough-32!", access_ttl=3600,
    )
    events = InMemoryEventPublisher()
    org_service = OrganizationService(factory, events)
    auth_service = AuthService(factory, hasher, tokens, events)
    target_service = AITargetService(factory, events)
    asset_service = TenantAssetService(factory)
    graph_service = TenantSecurityGraphService(factory)

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(org_router, prefix="/api/v1")
    test_app.include_router(targets_router, prefix="/api/v1")
    test_app.include_router(security_graph_router, prefix="/api/v1")

    test_app.dependency_overrides[get_auth_service] = lambda: auth_service
    test_app.dependency_overrides[get_organization_service] = lambda: org_service
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_effective_access_service] = lambda: _NoOpEffectiveAccessService()
    test_app.dependency_overrides[get_token_service] = lambda: tokens
    test_app.dependency_overrides[get_ai_target_service] = lambda: target_service
    test_app.dependency_overrides[get_tenant_asset_service] = lambda: asset_service
    test_app.dependency_overrides[get_tenant_security_graph_service] = lambda: graph_service

    return test_app


async def _register(client: AsyncClient, email: str) -> str:
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "display_name": "Test User", "password": "testpass123!"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["access_token"]


async def _scoped_org_token(client: AsyncClient, token: str, slug: str) -> str:
    org = await client.post(
        "/api/v1/organizations",
        json={"name": "Test Org", "slug": slug},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert org.status_code == 201, org.text
    org_id = org.json()["id"]
    sel = await client.post(
        f"/api/v1/auth/organizations/{org_id}/select",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert sel.status_code == 200, sel.text
    return sel.json()["access_token"]


@pytest.mark.asyncio
async def test_sentinel_secret_absent_from_security_graph_api(app):
    """The target `name` field is what the projector forwards as the
    node label; if a caller sneaks the sentinel into the target NAME
    itself, it's expected in the label (that's a display name, not a
    secret store). The real invariant this test proves: fields the
    projector does NOT forward (description, endpoint, provider) never
    appear anywhere in the graph API response, even though they live on
    the canonical AITarget/AIAsset the graph node was derived from.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "leak@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-leak")

        resp = await c.post(
            "/api/v1/targets",
            json={
                "name": "Leak Test Target",
                "target_type": "ai_api",
                "provider": "openai",
                "endpoint": f"https://api.openai.com/v1?key={_SENTINEL_SECRET}",
            },
            headers={"Authorization": f"Bearer {scoped}"},
        )
        assert resp.status_code == 201, resp.text

        overview = await c.get(
            "/api/v1/security-graph", headers={"Authorization": f"Bearer {scoped}"}
        )
        assert overview.status_code == 200
        body_text = overview.text
        assert _SENTINEL_SECRET not in body_text

        node_id = overview.json()["nodes"][0]["id"]
        node_detail = await c.get(
            f"/api/v1/security-graph/nodes/{node_id}",
            headers={"Authorization": f"Bearer {scoped}"},
        )
        assert _SENTINEL_SECRET not in node_detail.text
