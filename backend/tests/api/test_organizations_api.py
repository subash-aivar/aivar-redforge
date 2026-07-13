"""API integration tests for Organization endpoints.

Tests the full HTTP path: request → route → service → repo → response,
including authentication (create requires only a valid user) and
tenant-scoped authorization (read/rename/activate/deactivate require a
token scoped to that specific organization via the select-organization
flow).
Uses SQLite in-memory for a real persistence path.
"""

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
from redforge.api.v1.organizations import router
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
    """Create a test FastAPI app with real database."""
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
    test_app.include_router(router, prefix="/api/v1")
    test_app.include_router(auth_router, prefix="/api/v1")

    test_app.dependency_overrides[get_organization_service] = lambda: org_service
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_auth_service] = lambda: auth_service
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


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _register(client: AsyncClient, email: str) -> str:
    """Register a user and return their (unscoped) access token."""
    resp = await client.post("/api/v1/auth/register", json={
        "email": email, "display_name": "Test User", "password": "SecureP@ss123",
    })
    assert resp.status_code == 201, resp.text
    token: str = resp.json()["access_token"]
    return token


async def _create_org_and_select(
    client: AsyncClient, email: str, name: str, slug: str,
) -> tuple[str, str]:
    """Register, create an organization (auto OWNER membership), select
    it, and return (scoped_token, organization_id)."""
    unscoped = await _register(client, email)
    create_resp = await client.post(
        "/api/v1/organizations",
        json={"name": name, "slug": slug},
        headers=_auth_headers(unscoped),
    )
    assert create_resp.status_code == 201, create_resp.text
    org_id: str = create_resp.json()["id"]

    select_resp = await client.post(
        f"/api/v1/auth/organizations/{org_id}/select", headers=_auth_headers(unscoped),
    )
    assert select_resp.status_code == 200, select_resp.text
    scoped_token: str = select_resp.json()["access_token"]
    return scoped_token, org_id


class TestCreateOrganization:
    async def test_creates_successfully(self, client: AsyncClient) -> None:
        token = await _register(client, "creator1@test.com")
        resp = await client.post(
            "/api/v1/organizations",
            json={"name": "Acme Corp", "slug": "acme-corp", "plan": "enterprise"},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["name"] == "Acme Corp"
        assert body["slug"] == "acme-corp"
        assert body["plan"] == "enterprise"
        assert body["status"] == "active"
        assert "id" in body

    async def test_duplicate_slug_returns_409(self, client: AsyncClient) -> None:
        token = await _register(client, "creator2@test.com")
        await client.post(
            "/api/v1/organizations", json={"name": "First", "slug": "taken-slug"},
            headers=_auth_headers(token),
        )
        resp = await client.post(
            "/api/v1/organizations", json={"name": "Second", "slug": "taken-slug"},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 409

    async def test_invalid_slug_returns_422(self, client: AsyncClient) -> None:
        token = await _register(client, "creator3@test.com")
        resp = await client.post(
            "/api/v1/organizations", json={"name": "Valid Name", "slug": "INVALID"},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 422

    async def test_no_token_returns_401(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/api/v1/organizations", json={"name": "No Auth", "slug": "no-auth"},
        )
        assert resp.status_code == 401


class TestGetOrganization:
    async def test_gets_by_id(self, client: AsyncClient) -> None:
        token, org_id = await _create_org_and_select(
            client, "getter@test.com", "Get Org", "get-org",
        )
        resp = await client.get(
            f"/api/v1/organizations/{org_id}", headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Get Org"

    async def test_not_found_returns_404(self, client: AsyncClient) -> None:
        token, _org_id = await _create_org_and_select(
            client, "notfound@test.com", "Some Org", "some-org",
        )
        # A well-formed but different ULID is rejected as "not your token's
        # organization" before it would even be looked up — see
        # ensure_organization_match.
        resp = await client.get(
            "/api/v1/organizations/01HGW2N7HF0000000000000000",
            headers=_auth_headers(token),
        )
        assert resp.status_code in (403, 404)

    async def test_no_token_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/organizations/01HGW2N7HF0000000000000000")
        assert resp.status_code == 401

    async def test_cross_tenant_access_denied(self, client: AsyncClient) -> None:
        _token_a, org_a = await _create_org_and_select(
            client, "cta@test.com", "Org A", "org-a-get",
        )
        token_b, _org_b = await _create_org_and_select(
            client, "ctb@test.com", "Org B", "org-b-get",
        )
        # Org B's scoped token must not be able to read Org A by ID.
        resp = await client.get(
            f"/api/v1/organizations/{org_a}", headers=_auth_headers(token_b),
        )
        assert resp.status_code == 403


class TestRenameOrganization:
    async def test_renames(self, client: AsyncClient) -> None:
        token, org_id = await _create_org_and_select(
            client, "renamer@test.com", "Old Name", "rename-org",
        )
        resp = await client.patch(
            f"/api/v1/organizations/{org_id}/rename",
            json={"name": "New Name"},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "New Name"


class TestDeactivateActivate:
    async def test_deactivate_and_activate(self, client: AsyncClient) -> None:
        token, org_id = await _create_org_and_select(
            client, "lifecycle@test.com", "Lifecycle Org", "lifecycle-org",
        )
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/deactivate", headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "inactive"

        resp = await client.post(
            f"/api/v1/organizations/{org_id}/activate", headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "active"
