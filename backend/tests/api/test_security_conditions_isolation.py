"""Tenant isolation and safety adversarial tests for the M8 Security
Condition foundation."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_auth_service,
    get_effective_access_service,
    get_organization_service,
    get_tenant_asset_service,
    get_tenant_security_condition_service,
    get_token_service,
    get_user_status_service,
)
from redforge.api.v1.assets import router as assets_router
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.organizations import router as org_router
from redforge.api.v1.security_conditions import router as security_conditions_router
from redforge.application.auth import AuthService
from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.organizations import OrganizationService
from redforge.application.security_conditions.ingestion import (
    SecurityConditionInput,
    sanitize_evidence,
)
from redforge.application.security_conditions.service import TenantSecurityConditionService
from redforge.core.exceptions import NotFoundError
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
    UserModel,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware
from redforge.shared.identifiers import EntityId


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
    asset_service = TenantAssetService(factory)
    condition_service = TenantSecurityConditionService(factory)

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(org_router, prefix="/api/v1")
    test_app.include_router(assets_router, prefix="/api/v1")
    test_app.include_router(security_conditions_router, prefix="/api/v1")

    test_app.dependency_overrides[get_auth_service] = lambda: auth_service
    test_app.dependency_overrides[get_organization_service] = lambda: org_service
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_effective_access_service] = lambda: _NoOpEffectiveAccessService()
    test_app.dependency_overrides[get_token_service] = lambda: tokens
    test_app.dependency_overrides[get_tenant_asset_service] = lambda: asset_service
    test_app.dependency_overrides[get_tenant_security_condition_service] = lambda: condition_service

    return test_app, asset_service, condition_service


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


async def _make_host(asset_service: TenantAssetService, org_id: str, suffix: str) -> str:
    dto = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.HOST,
        scheme=IdentityScheme.DISCOVERY_HOST,
        raw_external_id=f"{EntityId.generate()}:host-{suffix}",
        name=f"host-{suffix}", description="", discovery_source=AssetDiscoverySource.API_SCAN,
    )
    return dto.id


def _condition_input(org_id: str, asset_id: str, **overrides) -> SecurityConditionInput:
    base = dict(
        organization_id=org_id, affected_asset_id=asset_id,
        source_category="network_discovery", stable_rule_id="SENSITIVE_SERVICE_OBSERVED",
        evidence_state="observed", severity="medium",
        title="Sensitive service observed", summary="SSH observed on host-1.",
    )
    base.update(overrides)
    return SecurityConditionInput(**base)


@pytest.mark.asyncio
async def test_tenant_a_condition_invisible_to_tenant_b(app):
    test_app, asset_service, condition_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        a_token = await _register(c, "a@redforge.test")
        a_scoped = await _scoped_org_token(c, a_token, "org-a")
        org_a = _decode_org(a_scoped)
        asset_id = await _make_host(asset_service, org_a, "1")
        condition = await condition_service.ingest(_condition_input(org_a, asset_id))

        b_token = await _register(c, "b@redforge.test")
        b_scoped = await _scoped_org_token(c, b_token, "org-b")

        listing = await c.get(
            "/api/v1/security-conditions", headers={"Authorization": f"Bearer {b_scoped}"}
        )
        assert listing.json() == []

        detail = await c.get(
            f"/api/v1/security-conditions/{condition.id}",
            headers={"Authorization": f"Bearer {b_scoped}"},
        )
        assert detail.status_code == 404


@pytest.mark.asyncio
async def test_summary_is_backend_aggregated_and_tenant_scoped(app):
    test_app, asset_service, condition_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        token = await _register(c, "u6@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-6")
        org_id = _decode_org(scoped)
        asset_1 = await _make_host(asset_service, org_id, "sum1")
        asset_2 = await _make_host(asset_service, org_id, "sum2")
        await condition_service.ingest(_condition_input(org_id, asset_1))
        await condition_service.ingest(_condition_input(org_id, asset_2))

        resp = await c.get(
            "/api/v1/security-conditions/summary", headers={"Authorization": f"Bearer {scoped}"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["by_evidence_state"] == {"observed": 2}
        assert body["by_severity"] == {"medium": 2}
        assert body["by_lifecycle"] == {"active": 2}


@pytest.mark.asyncio
async def test_guessed_foreign_condition_id_non_disclosing(app):
    test_app, _asset_service, _condition_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        token = await _register(c, "u1@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-1")
        resp = await c.get(
            f"/api/v1/security-conditions/{EntityId.generate()}",
            headers={"Authorization": f"Bearer {scoped}"},
        )
        assert resp.status_code == 404
        assert "organization_id" not in resp.text


@pytest.mark.asyncio
async def test_foreign_asset_cannot_be_attached(app):
    _test_app, asset_service, condition_service = app
    org_a, org_b = str(EntityId.generate()), str(EntityId.generate())
    asset_b = await _make_host(asset_service, org_b, "cross")
    with pytest.raises(NotFoundError):
        await condition_service.ingest(_condition_input(org_a, asset_b))


@pytest.mark.asyncio
async def test_same_condition_identity_two_tenants_remains_separate(app):
    _test_app, asset_service, condition_service = app
    org_a, org_b = str(EntityId.generate()), str(EntityId.generate())
    asset_a = await _make_host(asset_service, org_a, "a")
    asset_b = await _make_host(asset_service, org_b, "b")
    cond_a = await condition_service.ingest(_condition_input(org_a, asset_a))
    cond_b = await condition_service.ingest(_condition_input(org_b, asset_b))
    assert cond_a.id != cond_b.id


@pytest.mark.asyncio
async def test_repeated_ingestion_is_idempotent_and_updates_fields(app):
    _test_app, asset_service, condition_service = app
    org_id = str(EntityId.generate())
    asset_id = await _make_host(asset_service, org_id, "idem")
    first = await condition_service.ingest(_condition_input(org_id, asset_id, title="Old"))
    second = await condition_service.ingest(
        _condition_input(org_id, asset_id, title="New", summary="New summary")
    )
    assert first.id == second.id
    assert second.title == "New"


@pytest.mark.asyncio
async def test_same_rule_on_two_assets_remains_separate(app):
    _test_app, asset_service, condition_service = app
    org_id = str(EntityId.generate())
    asset_1 = await _make_host(asset_service, org_id, "1")
    asset_2 = await _make_host(asset_service, org_id, "2")
    cond_1 = await condition_service.ingest(_condition_input(org_id, asset_1))
    cond_2 = await condition_service.ingest(_condition_input(org_id, asset_2))
    assert cond_1.id != cond_2.id


@pytest.mark.asyncio
async def test_browser_cannot_declare_validated_or_forge_severity(app):
    """No API route accepts a SecurityConditionInput-shaped body at
    all — ingestion is an internal-only application boundary."""
    write_paths = {
        r.path for r in security_conditions_router.routes
        if "POST" in r.methods and not r.path.endswith("/resolve")
    }
    assert write_paths == set()


@pytest.mark.asyncio
async def test_raw_secret_absent_from_condition_api(app):
    test_app, asset_service, condition_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        token = await _register(c, "u2@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-2")
        org_id = _decode_org(scoped)
        asset_id = await _make_host(asset_service, org_id, "secret")

        sentinel_evidence = sanitize_evidence((
            ("aws_key", "AKIASENTINELTEST0000"),
            ("bearer", "Bearer sk-SENTINELTOKENVALUE12345"),
            ("private_key", "-----BEGIN RSA PRIVATE KEY-----\nSENTINELKEYDATA\n-----END RSA PRIVATE KEY-----"),
        ))
        condition = await condition_service.ingest(
            _condition_input(
                org_id, asset_id,
                evidence=tuple((e["label"], e["value"]) for e in sentinel_evidence),
            )
        )

        resp = await c.get(
            f"/api/v1/security-conditions/{condition.id}",
            headers={"Authorization": f"Bearer {scoped}"},
        )
        assert resp.status_code == 200
        assert "AKIASENTINELTEST0000" not in resp.text
        assert "sk-SENTINELTOKENVALUE12345" not in resp.text
        assert "SENTINELKEYDATA" not in resp.text


@pytest.mark.asyncio
async def test_oversized_evidence_bounded_and_truncation_explicit():
    long_value = "A" * 5000
    sanitized = sanitize_evidence(tuple((f"label-{i}", long_value) for i in range(20)))
    assert len(sanitized) == 5  # MAX_EVIDENCE_ITEMS
    assert all(e["truncated"] == "true" for e in sanitized)
    assert all(len(e["value"]) == 500 for e in sanitized)  # MAX_EVIDENCE_VALUE_LENGTH


@pytest.mark.asyncio
async def test_resolve_foreign_condition_denied_non_disclosing(app):
    test_app, asset_service, condition_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        a_token = await _register(c, "a4@redforge.test")
        a_scoped = await _scoped_org_token(c, a_token, "org-a4")
        org_a = _decode_org(a_scoped)
        asset_id = await _make_host(asset_service, org_a, "resolve")
        condition = await condition_service.ingest(_condition_input(org_a, asset_id))

        b_token = await _register(c, "b4@redforge.test")
        b_scoped = await _scoped_org_token(c, b_token, "org-b4")
        resp = await c.post(
            f"/api/v1/security-conditions/{condition.id}/resolve",
            headers={"Authorization": f"Bearer {b_scoped}"},
        )
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_resolved_condition_reobservation_reactivates_same_condition(app):
    _test_app, asset_service, condition_service = app
    org_id = str(EntityId.generate())
    asset_id = await _make_host(asset_service, org_id, "reactivate")
    created = await condition_service.ingest(_condition_input(org_id, asset_id))
    resolved = await condition_service.resolve_condition(created.id, org_id)
    assert resolved.lifecycle == "resolved"

    reobserved = await condition_service.ingest(_condition_input(org_id, asset_id))
    assert reobserved.id == created.id
    assert reobserved.lifecycle == "active"


@pytest.mark.asyncio
async def test_invalid_evidence_state_fails_safely(app):
    _test_app, asset_service, condition_service = app
    org_id = str(EntityId.generate())
    asset_id = await _make_host(asset_service, org_id, "badstate")
    from redforge.core.exceptions import ValidationError

    with pytest.raises(ValidationError):
        await condition_service.ingest(
            _condition_input(org_id, asset_id, evidence_state="not_a_real_state")
        )


@pytest.mark.asyncio
async def test_open_port_alone_not_automatically_a_vulnerability():
    """PUBLICLY_ADDRESSABLE_ASSET (a bare public-IP observation) is not
    in the network analyzer's severity map — it is never routed into a
    SecurityCondition as a vulnerability, only served as a live
    read-time observation."""
    from redforge.application.network_discovery.service import _RULE_SEVERITY

    assert "SENSITIVE_SERVICE_OBSERVED" in _RULE_SEVERITY
    assert _RULE_SEVERITY["PUBLICLY_ADDRESSABLE_ASSET"] == "informational"


@pytest.mark.asyncio
async def test_unauthenticated_denied(app):
    test_app, _asset_service, _condition_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        resp = await c.get("/api/v1/security-conditions")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_no_generic_condition_creation_endpoint() -> None:
    write_paths = {r.path for r in security_conditions_router.routes if "POST" in r.methods}
    assert all(p.endswith("/resolve") for p in write_paths)
