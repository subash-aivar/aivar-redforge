"""API tests for GET /api/v1/auth/organizations — accessible organization discovery.

Tenant isolation requirements:
- User A sees only A's active-membership organizations.
- User A cannot discover unrelated organization B.
- Inactive membership does not grant discovery.
- User B cannot discover A-only organizations.
- First-time user with no memberships sees empty list.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_auth_service,
    get_organization_service,
    get_token_service,
    get_user_status_service,
)
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.organizations import router as org_router
from redforge.application.auth import AuthService
from redforge.application.organizations import OrganizationService
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (  # noqa: F401
    MembershipModel,
    OrganizationModel,
    UserModel,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware


@pytest.fixture
async def app() -> FastAPI:
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    events = InMemoryEventPublisher()
    hasher = Argon2PasswordHasher(time_cost=1, memory_cost=16384, parallelism=1)
    tokens = JWTTokenService(
        secret_key="test-secret-key-that-is-long-enough-32!", access_ttl=3600,
    )
    org_service = OrganizationService(factory, events)
    auth_service = AuthService(factory, hasher, tokens, events)

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(org_router, prefix="/api/v1")

    test_app.dependency_overrides[get_auth_service] = lambda: auth_service
    test_app.dependency_overrides[get_organization_service] = lambda: org_service
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_token_service] = lambda: tokens

    yield test_app
    await engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncClient:
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac



class _AlwaysActiveUserStatusService:
    """Test double: every user is ACTIVE. Real suspension-enforcement
    tests live in tests/api/test_platform_identity_api.py; this fake
    just keeps pre-existing fixtures unaffected by the new M2
    live-user-status check in api/security.py.
    """

    async def get_status(self, user_id: str) -> str:
        return "active"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _register(client: AsyncClient, email: str) -> str:
    resp = await client.post("/api/v1/auth/register", json={
        "email": email, "display_name": "Test", "password": "SecureP@ss123",
    })
    assert resp.status_code == 201, resp.text
    token: str = resp.json()["access_token"]
    return token


async def _create_org(client: AsyncClient, token: str, name: str, slug: str) -> str:
    resp = await client.post(
        "/api/v1/organizations",
        json={"name": name, "slug": slug},
        headers=_auth(token),
    )
    assert resp.status_code == 201, resp.text
    org_id: str = resp.json()["id"]
    return org_id


class TestOrgDiscovery:
    async def test_no_memberships_returns_empty(self, client: AsyncClient) -> None:
        token = await _register(client, "disc-empty@test.com")
        resp = await client.get("/api/v1/auth/organizations", headers=_auth(token))
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_returns_own_organization(self, client: AsyncClient) -> None:
        token = await _register(client, "disc-own@test.com")
        org_id = await _create_org(client, token, "My Org", "my-org-disc")

        resp = await client.get("/api/v1/auth/organizations", headers=_auth(token))
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        assert body[0]["id"] == org_id
        assert body[0]["name"] == "My Org"
        assert "id" in body[0]
        assert "slug" in body[0]
        assert "status" in body[0]
        assert "plan" in body[0]

    async def test_user_a_cannot_discover_user_b_organization(
        self, client: AsyncClient,
    ) -> None:
        token_a = await _register(client, "disc-a@test.com")
        token_b = await _register(client, "disc-b@test.com")

        org_b_id = await _create_org(client, token_b, "Org B", "org-b-disc")

        resp_a = await client.get("/api/v1/auth/organizations", headers=_auth(token_a))
        assert resp_a.status_code == 200
        ids_a = [o["id"] for o in resp_a.json()]
        assert org_b_id not in ids_a, "User A must not discover Org B"

    async def test_user_b_cannot_discover_user_a_organization(
        self, client: AsyncClient,
    ) -> None:
        token_a = await _register(client, "disc-xa@test.com")
        token_b = await _register(client, "disc-xb@test.com")

        org_a_id = await _create_org(client, token_a, "Org A Only", "org-a-only-disc")

        resp_b = await client.get("/api/v1/auth/organizations", headers=_auth(token_b))
        assert resp_b.status_code == 200
        ids_b = [o["id"] for o in resp_b.json()]
        assert org_a_id not in ids_b, "User B must not discover Org A"

    async def test_no_token_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/auth/organizations")
        assert resp.status_code == 401

    async def test_multiple_orgs_returned_for_member(self, client: AsyncClient) -> None:
        token = await _register(client, "disc-multi@test.com")
        id1 = await _create_org(client, token, "Multi Org 1", "multi-disc-1")
        id2 = await _create_org(client, token, "Multi Org 2", "multi-disc-2")

        resp = await client.get("/api/v1/auth/organizations", headers=_auth(token))
        assert resp.status_code == 200
        ids = {o["id"] for o in resp.json()}
        assert id1 in ids
        assert id2 in ids

    async def test_schema_fields_present(self, client: AsyncClient) -> None:
        token = await _register(client, "disc-schema@test.com")
        await _create_org(client, token, "Schema Org", "schema-org-disc")

        resp = await client.get("/api/v1/auth/organizations", headers=_auth(token))
        assert resp.status_code == 200
        org = resp.json()[0]
        for field in ("id", "name", "slug", "status", "plan"):
            assert field in org, f"Missing field: {field}"
