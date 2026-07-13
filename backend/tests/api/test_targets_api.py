"""API regression tests for AI Target request contract.

Covers:
- Invalid target_type ("llm") → 422, never 500
- Every canonical TargetType value → 201 (request validation pass)
- Every canonical Provider value → 201 (request validation pass)
- Invalid provider value → 422, never 500
- Tenant isolation: list/get scoped to org
"""

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
    get_token_service,
    get_user_status_service,
)
from redforge.api.v1.ai_targets import router as targets_router
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.organizations import router as org_router
from redforge.application.ai_targets import AITargetService
from redforge.application.auth import AuthService
from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.organizations import OrganizationService
from redforge.domain.ai_targets.value_objects import Provider, TargetType
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (  # noqa: F401
    AIAssetModel,
    AITargetModel,
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
    target_service = AITargetService(factory, events)
    asset_service = TenantAssetService(factory)

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(org_router, prefix="/api/v1")
    test_app.include_router(targets_router, prefix="/api/v1")

    test_app.dependency_overrides[get_auth_service] = lambda: auth_service
    test_app.dependency_overrides[get_organization_service] = lambda: org_service
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_token_service] = lambda: tokens
    test_app.dependency_overrides[get_ai_target_service] = lambda: target_service
    test_app.dependency_overrides[get_tenant_asset_service] = lambda: asset_service

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


async def _scoped_token(client: AsyncClient, email: str, org_slug: str) -> tuple[str, str]:
    """Register user, create org, return (scoped_token, org_id)."""
    reg = await client.post("/api/v1/auth/register", json={
        "email": email, "display_name": "Test User", "password": "SecureP@ss123",
    })
    assert reg.status_code == 201, reg.text
    unscoped = reg.json()["access_token"]

    org_resp = await client.post(
        "/api/v1/organizations",
        json={"name": f"Org {org_slug}", "slug": org_slug},
        headers=_auth_headers(unscoped),
    )
    assert org_resp.status_code == 201, org_resp.text
    org_id: str = org_resp.json()["id"]

    sel = await client.post(
        f"/api/v1/auth/organizations/{org_id}/select",
        headers=_auth_headers(unscoped),
    )
    assert sel.status_code == 200, sel.text
    return sel.json()["access_token"], org_id


def _target_payload(
    target_type: str = "llm_application",
    provider: str = "openai",
) -> dict:
    return {
        "name": "Test Target",
        "description": "regression",
        "target_type": target_type,
        "provider": provider,
        "endpoint": "https://api.openai.com/v1",
    }


# ─── TargetType Validation ────────────────────────────────────────────────────


class TestTargetTypeValidation:
    """Request-layer validation for target_type enum."""

    async def test_invalid_target_type_llm_returns_422(self, client: AsyncClient) -> None:
        """'llm' is not canonical — must 422, never reach application layer."""
        token, _ = await _scoped_token(client, "t1@test.com", "org-t1")
        resp = await client.post(
            "/api/v1/targets",
            json=_target_payload(target_type="llm"),
            headers=_auth_headers(token),
        )
        assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text}"

    async def test_invalid_target_type_never_500(self, client: AsyncClient) -> None:
        """Validation error must not bubble as 500."""
        token, _ = await _scoped_token(client, "t2@test.com", "org-t2")
        resp = await client.post(
            "/api/v1/targets",
            json=_target_payload(target_type="unknown_type"),
            headers=_auth_headers(token),
        )
        assert resp.status_code != 500, f"Invalid type produced 500: {resp.text}"
        assert resp.status_code == 422

    @pytest.mark.parametrize("target_type", list(TargetType))
    async def test_canonical_target_type_accepted(
        self, client: AsyncClient, target_type: TargetType,
    ) -> None:
        """Every canonical TargetType value must pass request validation → 201."""
        slug = target_type.value.replace("_", "-")
        email = f"tt-{slug}@test.com"
        token, _ = await _scoped_token(client, email, f"org-tt-{slug}"[:50])
        resp = await client.post(
            "/api/v1/targets",
            json=_target_payload(target_type=target_type.value),
            headers=_auth_headers(token),
        )
        assert resp.status_code == 201, (
            f"TargetType.{target_type} rejected at request layer: {resp.status_code} {resp.text}"
        )


# ─── Provider Validation ──────────────────────────────────────────────────────


class TestProviderValidation:
    """Request-layer validation for provider enum."""

    async def test_invalid_provider_returns_422(self, client: AsyncClient) -> None:
        token, _ = await _scoped_token(client, "p1@test.com", "org-p1")
        resp = await client.post(
            "/api/v1/targets",
            json=_target_payload(provider="invalid_provider_xyz"),
            headers=_auth_headers(token),
        )
        assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text}"

    async def test_invalid_provider_never_500(self, client: AsyncClient) -> None:
        token, _ = await _scoped_token(client, "p2@test.com", "org-p2")
        resp = await client.post(
            "/api/v1/targets",
            json=_target_payload(provider="bad"),
            headers=_auth_headers(token),
        )
        assert resp.status_code != 500
        assert resp.status_code == 422

    @pytest.mark.parametrize("provider", list(Provider))
    async def test_canonical_provider_accepted(
        self, client: AsyncClient, provider: Provider,
    ) -> None:
        """Every canonical Provider value must pass request validation → 201."""
        slug = provider.value.replace("_", "-")
        email = f"prov-{slug}@test.com"
        token, _ = await _scoped_token(client, email, f"org-prov-{slug}"[:50])
        resp = await client.post(
            "/api/v1/targets",
            json=_target_payload(provider=provider.value),
            headers=_auth_headers(token),
        )
        assert resp.status_code == 201, (
            f"Provider.{provider} rejected at request layer: {resp.status_code} {resp.text}"
        )


# ─── Tenant Isolation ─────────────────────────────────────────────────────────


class TestTargetTenantIsolation:
    """Organization-scoped target list/get isolation."""

    async def test_list_returns_own_targets_only(self, client: AsyncClient) -> None:
        token_a, _ = await _scoped_token(client, "iso-a@test.com", "org-iso-a")
        token_b, _ = await _scoped_token(client, "iso-b@test.com", "org-iso-b")

        cr = await client.post(
            "/api/v1/targets",
            json=_target_payload(),
            headers=_auth_headers(token_a),
        )
        assert cr.status_code == 201
        target_id = cr.json()["id"]

        list_b = await client.get("/api/v1/targets", headers=_auth_headers(token_b))
        assert list_b.status_code == 200
        ids_b = [t["id"] for t in list_b.json()]
        assert target_id not in ids_b, "Org B should not see Org A's targets"

    async def test_get_cross_tenant_returns_404(self, client: AsyncClient) -> None:
        token_a, _ = await _scoped_token(client, "xten-a@test.com", "org-xten-a")
        token_b, _ = await _scoped_token(client, "xten-b@test.com", "org-xten-b")

        cr = await client.post(
            "/api/v1/targets",
            json=_target_payload(),
            headers=_auth_headers(token_a),
        )
        assert cr.status_code == 201
        target_id = cr.json()["id"]

        get_b = await client.get(
            f"/api/v1/targets/{target_id}",
            headers=_auth_headers(token_b),
        )
        assert get_b.status_code in (403, 404), (
            f"Cross-tenant GET should return 403/404, got {get_b.status_code}"
        )
