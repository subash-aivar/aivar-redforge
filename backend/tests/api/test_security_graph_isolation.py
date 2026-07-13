"""Tenant isolation adversarial tests for the M4 Security Graph foundation."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_ai_target_service,
    get_auth_service,
    get_organization_service,
    get_tenant_asset_service,
    get_tenant_security_graph_service,
    get_token_service,
    get_user_status_service,
)
from redforge.api.v1.ai_targets import router as targets_router
from redforge.api.v1.assets import router as assets_router
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
from redforge.infrastructure.database.models import (  # noqa: F401
    AIAssetModel,
    AITargetModel,
    MembershipModel,
    OrganizationModel,
    SecurityGraphEdgeModel,
    SecurityGraphNodeModel,
    UserModel,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware


class _AlwaysActiveUserStatusService:
    async def get_status(self, user_id: str) -> str:
        return "active"


@pytest.fixture
async def engine():
    eng = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
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
    test_app.include_router(assets_router, prefix="/api/v1")
    test_app.include_router(security_graph_router, prefix="/api/v1")

    test_app.dependency_overrides[get_auth_service] = lambda: auth_service
    test_app.dependency_overrides[get_organization_service] = lambda: org_service
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
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


async def _create_target(client: AsyncClient, token: str, name: str) -> str:
    resp = await client.post(
        "/api/v1/targets",
        json={
            "name": name, "target_type": "ai_api", "provider": "openai",
            "endpoint": "https://api.openai.com/v1",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _graph_node_id_for_asset(client: AsyncClient, token: str) -> str:
    overview = await client.get(
        "/api/v1/security-graph", headers={"Authorization": f"Bearer {token}"}
    )
    assert overview.status_code == 200
    nodes = overview.json()["nodes"]
    assert len(nodes) == 1
    return nodes[0]["id"]


@pytest.mark.asyncio
async def test_tenant_a_node_invisible_to_tenant_b(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        a_token = await _register(c, "a@redforge.test")
        a_scoped = await _scoped_org_token(c, a_token, "org-a")
        await _create_target(c, a_scoped, "Target A")
        node_id = await _graph_node_id_for_asset(c, a_scoped)

        b_token = await _register(c, "b@redforge.test")
        b_scoped = await _scoped_org_token(c, b_token, "org-b")

        b_overview = await c.get(
            "/api/v1/security-graph", headers={"Authorization": f"Bearer {b_scoped}"}
        )
        assert b_overview.status_code == 200
        assert b_overview.json()["nodes"] == []

        b_get = await c.get(
            f"/api/v1/security-graph/nodes/{node_id}",
            headers={"Authorization": f"Bearer {b_scoped}"},
        )
        assert b_get.status_code == 404


@pytest.mark.asyncio
async def test_guessed_node_id_denied(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "u1@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-1")
        resp = await c.get(
            "/api/v1/security-graph/nodes/01NONEXISTENTGUESSEDID0000",
            headers={"Authorization": f"Bearer {scoped}"},
        )
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_same_source_identity_across_tenants_remains_separate(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        a_token = await _register(c, "a2@redforge.test")
        a_scoped = await _scoped_org_token(c, a_token, "org-a2")
        await _create_target(c, a_scoped, "Same Name")
        node_a = await _graph_node_id_for_asset(c, a_scoped)

        b_token = await _register(c, "b2@redforge.test")
        b_scoped = await _scoped_org_token(c, b_token, "org-b2")
        await _create_target(c, b_scoped, "Same Name")
        node_b = await _graph_node_id_for_asset(c, b_scoped)

        assert node_a != node_b


@pytest.mark.asyncio
async def test_neighbor_query_never_crosses_tenant_boundary(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        a_token = await _register(c, "a3@redforge.test")
        a_scoped = await _scoped_org_token(c, a_token, "org-a3")
        await _create_target(c, a_scoped, "Target A3")
        node_id = await _graph_node_id_for_asset(c, a_scoped)

        b_token = await _register(c, "b3@redforge.test")
        b_scoped = await _scoped_org_token(c, b_token, "org-b3")

        resp = await c.get(
            f"/api/v1/security-graph/nodes/{node_id}/neighbors",
            headers={"Authorization": f"Bearer {b_scoped}"},
        )
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_path_query_foreign_start_node_denied(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        a_token = await _register(c, "a4@redforge.test")
        a_scoped = await _scoped_org_token(c, a_token, "org-a4")
        await _create_target(c, a_scoped, "Target A4")
        node_id = await _graph_node_id_for_asset(c, a_scoped)

        b_token = await _register(c, "b4@redforge.test")
        b_scoped = await _scoped_org_token(c, b_token, "org-b4")
        await _create_target(c, b_scoped, "Target B4")
        b_node_id = await _graph_node_id_for_asset(c, b_scoped)

        resp = await c.post(
            "/api/v1/security-graph/paths/query",
            json={"start_node_id": node_id, "end_node_id": b_node_id, "max_depth": 3},
            headers={"Authorization": f"Bearer {b_scoped}"},
        )
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_path_query_invalid_relationship_filter_rejected(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "u5@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-5")
        await _create_target(c, scoped, "Target 5")
        node_id = await _graph_node_id_for_asset(c, scoped)

        resp = await c.post(
            "/api/v1/security-graph/paths/query",
            json={
                "start_node_id": node_id, "end_node_id": node_id, "max_depth": 3,
                "relationship_kinds": ["not_a_real_kind"],
            },
            headers={"Authorization": f"Bearer {scoped}"},
        )
        assert resp.status_code == 400


@pytest.mark.asyncio
async def test_path_query_max_depth_clamped_server_side(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "u6@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-6")
        await _create_target(c, scoped, "Target 6")
        node_id = await _graph_node_id_for_asset(c, scoped)

        resp = await c.post(
            "/api/v1/security-graph/paths/query",
            json={
                "start_node_id": node_id, "end_node_id": node_id, "max_depth": 999999,
            },
            headers={"Authorization": f"Bearer {scoped}"},
        )
        # server clamps depth internally; a self-path with no edges returns empty, not an error
        assert resp.status_code == 200
        assert resp.json()["paths"] == []


@pytest.mark.asyncio
async def test_unauthenticated_denied(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/api/v1/security-graph")
        assert resp.status_code == 401


def test_no_public_node_or_edge_write_endpoints() -> None:
    """There is deliberately no POST /security-graph/nodes or /edges —
    the graph is a projection, never directly writable by a browser
    client."""
    write_paths = {
        r.path for r in security_graph_router.routes if "POST" in r.methods
    }
    assert write_paths == {"/security-graph/paths/query"}
