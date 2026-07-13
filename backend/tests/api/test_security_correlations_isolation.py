"""Tenant isolation and safety adversarial tests for the M9 Security
Correlation / Attack Surface foundation."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_auth_service,
    get_organization_service,
    get_tenant_asset_service,
    get_tenant_attack_surface_service,
    get_tenant_security_condition_service,
    get_tenant_security_correlation_service,
    get_token_service,
    get_user_status_service,
)
from redforge.api.v1.assets import router as assets_router
from redforge.api.v1.attack_surface import router as attack_surface_router
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.organizations import router as org_router
from redforge.api.v1.security_correlations import router as security_correlations_router
from redforge.application.auth import AuthService
from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.organizations import OrganizationService
from redforge.application.security_conditions.ingestion import SecurityConditionInput
from redforge.application.security_conditions.service import TenantSecurityConditionService
from redforge.application.security_correlation.attack_surface import TenantAttackSurfaceService
from redforge.application.security_correlation.rules import (
    CorrelationRuleRegistry,
    MultipleSecurityConditionsOnAssetRule,
    PublicSensitiveServiceContextRule,
)
from redforge.application.security_correlation.service import TenantSecurityCorrelationService
from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import AssetDiscoverySource, AssetType
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (  # noqa: F401
    AIAssetModel,
    MembershipModel,
    OrganizationModel,
    SecurityConditionModel,
    SecurityCorrelationConditionModel,
    SecurityCorrelationEntityModel,
    SecurityCorrelationModel,
    UserModel,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware
from redforge.shared.identifiers import EntityId


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
    asset_service = TenantAssetService(factory)
    condition_service = TenantSecurityConditionService(factory)
    registry = CorrelationRuleRegistry()
    registry.register(PublicSensitiveServiceContextRule(asset_service, condition_service))
    registry.register(MultipleSecurityConditionsOnAssetRule(condition_service))
    correlation_service = TenantSecurityCorrelationService(factory, registry)
    attack_surface_service = TenantAttackSurfaceService(
        asset_service, condition_service, correlation_service,
    )

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(org_router, prefix="/api/v1")
    test_app.include_router(assets_router, prefix="/api/v1")
    test_app.include_router(security_correlations_router, prefix="/api/v1")
    test_app.include_router(attack_surface_router, prefix="/api/v1")

    test_app.dependency_overrides[get_auth_service] = lambda: auth_service
    test_app.dependency_overrides[get_organization_service] = lambda: org_service
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_token_service] = lambda: tokens
    test_app.dependency_overrides[get_tenant_asset_service] = lambda: asset_service
    test_app.dependency_overrides[get_tenant_security_condition_service] = lambda: condition_service
    test_app.dependency_overrides[get_tenant_security_correlation_service] = (
        lambda: correlation_service
    )
    test_app.dependency_overrides[get_tenant_attack_surface_service] = lambda: attack_surface_service

    return test_app, asset_service, condition_service, correlation_service


async def _register(client: AsyncClient, email: str) -> str:
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "display_name": "Test User", "password": "testpass123!"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["access_token"]


async def _scoped_org_token(client: AsyncClient, token: str, slug: str) -> str:
    org = await client.post(
        "/api/v1/organizations", json={"name": "Test Org", "slug": slug},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert org.status_code == 201, org.text
    org_id = org.json()["id"]
    sel = await client.post(
        f"/api/v1/auth/organizations/{org_id}/select", headers={"Authorization": f"Bearer {token}"},
    )
    assert sel.status_code == 200, sel.text
    return sel.json()["access_token"]


def _decode_org(token: str) -> str:
    import jwt

    return jwt.decode(token, options={"verify_signature": False})["org"]


async def _make_host_with_two_conditions(asset_service, condition_service, org_id: str) -> str:
    host = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.HOST,
        scheme=IdentityScheme.DISCOVERY_HOST, raw_external_id=f"{EntityId.generate()}:api-host",
        name="api-host", description="", discovery_source=AssetDiscoverySource.API_SCAN,
    )
    await condition_service.ingest(SecurityConditionInput(
        organization_id=org_id, affected_asset_id=host.id, source_category="network_discovery",
        stable_rule_id="SENSITIVE_SERVICE_OBSERVED", evidence_state="observed", severity="medium",
        title="A", summary="A",
    ))
    await condition_service.ingest(SecurityConditionInput(
        organization_id=org_id, affected_asset_id=host.id, source_category="network_discovery",
        stable_rule_id="MULTIPLE_REMOTE_ADMIN_SERVICES", evidence_state="observed", severity="high",
        title="B", summary="B",
    ))
    return host.id


@pytest.mark.asyncio
async def test_tenant_a_correlation_invisible_to_tenant_b(app):
    test_app, asset_service, condition_service, correlation_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        a_token = await _register(c, "a@redforge.test")
        a_scoped = await _scoped_org_token(c, a_token, "org-a")
        org_a = _decode_org(a_scoped)
        await _make_host_with_two_conditions(asset_service, condition_service, org_a)
        await correlation_service.evaluate(org_a)
        correlation_id = (await correlation_service.list_for_org(org_a))[0].id

        b_token = await _register(c, "b@redforge.test")
        b_scoped = await _scoped_org_token(c, b_token, "org-b")

        listing = await c.get(
            "/api/v1/security-correlations", headers={"Authorization": f"Bearer {b_scoped}"}
        )
        assert listing.json() == []

        detail = await c.get(
            f"/api/v1/security-correlations/{correlation_id}",
            headers={"Authorization": f"Bearer {b_scoped}"},
        )
        assert detail.status_code == 404


@pytest.mark.asyncio
async def test_guessed_foreign_correlation_id_non_disclosing(app):
    test_app, *_ = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        token = await _register(c, "u1@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-1")
        resp = await c.get(
            f"/api/v1/security-correlations/{EntityId.generate()}",
            headers={"Authorization": f"Bearer {scoped}"},
        )
        assert resp.status_code == 404
        assert "organization_id" not in resp.text


@pytest.mark.asyncio
async def test_evaluate_via_api_creates_correlation_and_is_idempotent(app):
    test_app, asset_service, condition_service, _correlation_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        token = await _register(c, "u2@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-2")
        org_id = _decode_org(scoped)
        await _make_host_with_two_conditions(asset_service, condition_service, org_id)

        eval_1 = await c.post(
            "/api/v1/security-correlations/evaluate", headers={"Authorization": f"Bearer {scoped}"}
        )
        assert eval_1.status_code == 200
        assert eval_1.json()["created"] == 1

        eval_2 = await c.post(
            "/api/v1/security-correlations/evaluate", headers={"Authorization": f"Bearer {scoped}"}
        )
        assert eval_2.json()["created"] == 0
        assert eval_2.json()["updated"] == 1

        listing = await c.get(
            "/api/v1/security-correlations", headers={"Authorization": f"Bearer {scoped}"}
        )
        assert len(listing.json()) == 1


@pytest.mark.asyncio
async def test_no_endpoint_accepts_correlation_creation_body(app):
    """The only POST route is `/evaluate` — no endpoint accepts a
    caller-supplied correlation body, evidence_state, or rule input."""
    write_paths = {r.path for r in security_correlations_router.routes if "POST" in r.methods}
    assert all(p.endswith("/evaluate") for p in write_paths)


@pytest.mark.asyncio
async def test_no_public_write_endpoints_on_attack_surface_router() -> None:
    write_paths = {r.path for r in attack_surface_router.routes if "POST" in r.methods}
    assert write_paths == set()


@pytest.mark.asyncio
async def test_attack_surface_summary_backend_computed(app):
    test_app, asset_service, condition_service, correlation_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        token = await _register(c, "u3@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-3")
        org_id = _decode_org(scoped)
        await _make_host_with_two_conditions(asset_service, condition_service, org_id)
        await correlation_service.evaluate(org_id)

        resp = await c.get(
            "/api/v1/attack-surface/summary", headers={"Authorization": f"Bearer {scoped}"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["assets_with_active_conditions"] == 1
        assert body["assets_with_multiple_active_conditions"] == 1
        assert body["active_correlations"] == 1


@pytest.mark.asyncio
async def test_asset_exposure_summary_cross_tenant_denied(app):
    test_app, asset_service, condition_service, _correlation_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        a_token = await _register(c, "a4@redforge.test")
        a_scoped = await _scoped_org_token(c, a_token, "org-a4")
        org_a = _decode_org(a_scoped)
        host_id = await _make_host_with_two_conditions(asset_service, condition_service, org_a)

        b_token = await _register(c, "b4@redforge.test")
        b_scoped = await _scoped_org_token(c, b_token, "org-b4")
        resp = await c.get(
            f"/api/v1/attack-surface/assets/{host_id}", headers={"Authorization": f"Bearer {b_scoped}"}
        )
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_asset_exposure_summary_no_magic_score(app):
    test_app, asset_service, condition_service, correlation_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        token = await _register(c, "u5@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-5")
        org_id = _decode_org(scoped)
        host_id = await _make_host_with_two_conditions(asset_service, condition_service, org_id)
        await correlation_service.evaluate(org_id)

        resp = await c.get(
            f"/api/v1/attack-surface/assets/{host_id}", headers={"Authorization": f"Bearer {scoped}"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "risk_score" not in body
        assert body["active_condition_count"] == 2
        assert body["highest_active_severity"] == "high"
        assert body["active_correlation_count"] == 1


@pytest.mark.asyncio
async def test_unauthenticated_denied(app):
    test_app, *_ = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        resp = await c.get("/api/v1/security-correlations")
        assert resp.status_code == 401
        resp2 = await c.get("/api/v1/attack-surface/summary")
        assert resp2.status_code == 401
