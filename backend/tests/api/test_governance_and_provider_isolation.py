"""M2 adversarial tests:
  - User suspension invalidates effective access for already-issued tokens
  - Organization suspension invalidates effective access for already-issued
    org-scoped tokens
  - Self-suspension protection
  - Cross-tenant provider isolation (list/get/campaign-select/credential
    resolution)

Uses SQLite for API-boundary correctness — this file does not claim to
prove concurrency-sensitive invariants (those live in the PostgreSQL
integration test suite).
"""

from __future__ import annotations

import pyotp
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_ai_target_service,
    get_assurance_service,
    get_auth_service,
    get_mfa_service,
    get_organization_service,
    get_platform_access_service,
    get_platform_governance_service,
    get_platform_query_service,
    get_provider_service,
    get_token_service,
    get_user_status_service,
)
from redforge.api.v1.ai_targets import router as targets_router
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.organizations import router as org_router
from redforge.api.v1.platform import router as platform_router
from redforge.api.v1.providers import router as providers_router
from redforge.application.ai_targets import AITargetService
from redforge.application.auth import AuthService, UserStatusService
from redforge.application.mfa import MFAService, PrivilegedAssuranceService
from redforge.application.organizations import OrganizationService
from redforge.application.platform_identity import (
    PlatformAccessService,
    PlatformQueryService,
)
from redforge.application.platform_identity.governance_service import (
    PlatformGovernanceService,
)
from redforge.application.providers import ProviderService
from redforge.core.config import Settings
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (  # noqa: F401
    AITargetModel,
    CampaignResultModel,
    MembershipModel,
    MFAFactorModel,
    OrganizationModel,
    PlatformAssignmentModel,
    PlatformAuditLogModel,
    PlatformBootstrapStateModel,
    PlatformPrivilegedAssuranceModel,
    UserModel,
)
from redforge.infrastructure.database.unit_of_work import UnitOfWork
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware

_TEST_MFA_KEY = "JCBz3tgnOeWF7cKJJpMOD9iTL4pc0h9KLX3kgCyj-9g="
_BOOTSTRAP_EMAIL = "owner@redforge.test"


@pytest.fixture
async def engine():
    eng = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(
            text(
                "CREATE TABLE IF NOT EXISTS providers (id TEXT PRIMARY KEY, data JSON NOT NULL)"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO platform_bootstrap_state (id, consumed_at, consumed_by) "
                "VALUES ('singleton', NULL, NULL)"
            )
        )
    yield eng
    await eng.dispose()


@pytest.fixture
async def factory(engine):
    from sqlalchemy.ext.asyncio import AsyncSession

    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture
def app(factory):
    hasher = Argon2PasswordHasher(time_cost=1, memory_cost=16384, parallelism=1)
    token_svc = JWTTokenService(
        secret_key="test-secret-key-that-is-long-enough-32!", access_ttl=3600,
    )
    publisher = InMemoryEventPublisher()

    auth_svc = AuthService(
        session_factory=factory, password_hasher=hasher,
        token_service=token_svc, event_publisher=publisher,
    )
    org_svc = OrganizationService(session_factory=factory, event_publisher=publisher)
    settings = Settings(
        environment="test",
        jwt_secret="test-secret-key-that-is-long-enough-32!",
        platform_bootstrap_enabled=True,
        platform_bootstrap_principal_email=_BOOTSTRAP_EMAIL,
    )
    platform_access_svc = PlatformAccessService(factory, settings)
    platform_query_svc = PlatformQueryService(factory)
    platform_governance_svc = PlatformGovernanceService(factory, org_svc)
    mfa_svc = MFAService(factory, _TEST_MFA_KEY)
    assurance_svc = PrivilegedAssuranceService(factory, mfa_svc, ttl_seconds=300)
    user_status_svc = UserStatusService(factory)
    provider_svc = ProviderService(lambda: UnitOfWork(factory))
    target_svc = AITargetService(factory, publisher)

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(org_router, prefix="/api/v1")
    test_app.include_router(platform_router, prefix="/api/v1")
    test_app.include_router(providers_router, prefix="/api/v1")
    test_app.include_router(targets_router, prefix="/api/v1")

    test_app.dependency_overrides[get_token_service] = lambda: token_svc
    test_app.dependency_overrides[get_auth_service] = lambda: auth_svc
    test_app.dependency_overrides[get_organization_service] = lambda: org_svc
    test_app.dependency_overrides[get_user_status_service] = lambda: user_status_svc
    test_app.dependency_overrides[get_platform_access_service] = lambda: platform_access_svc
    test_app.dependency_overrides[get_platform_query_service] = lambda: platform_query_svc
    test_app.dependency_overrides[get_platform_governance_service] = lambda: platform_governance_svc
    test_app.dependency_overrides[get_mfa_service] = lambda: mfa_svc
    test_app.dependency_overrides[get_assurance_service] = lambda: assurance_svc
    test_app.dependency_overrides[get_provider_service] = lambda: provider_svc
    test_app.dependency_overrides[get_ai_target_service] = lambda: target_svc

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


async def _bootstrap_and_assurance(client: AsyncClient, token: str) -> str:
    headers = {"Authorization": f"Bearer {token}"}
    boot = await client.post("/api/v1/platform/bootstrap", headers=headers)
    assert boot.status_code == 201, boot.text
    begin = await client.post("/api/v1/platform/mfa/enroll/begin", headers=headers)
    secret = begin.json()["secret"]
    await client.post(
        "/api/v1/platform/mfa/enroll/verify",
        json={"enrollment_id": begin.json()["enrollment_id"], "code": pyotp.TOTP(secret).now()},
        headers=headers,
    )
    step_up = await client.post(
        "/api/v1/platform/assurance/step-up",
        json={"code": pyotp.TOTP(secret).now()},
        headers=headers,
    )
    return step_up.json()["assurance_token"]


# ─── User suspension ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_suspend_user_invalidates_effective_access_despite_valid_jwt(app):
    """The core M2 proof: a JWT issued BEFORE suspension is still
    cryptographically valid and unexpired, but must be denied AFTER
    suspension — proving the live user-status check, not JWT expiry,
    is what's doing the work.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        owner_token = await _register(c, _BOOTSTRAP_EMAIL)
        assurance = await _bootstrap_and_assurance(c, owner_token)
        owner_headers = {"Authorization": f"Bearer {owner_token}"}

        victim_token = await _register(c, "victim@redforge.test")
        victim_headers = {"Authorization": f"Bearer {victim_token}"}
        victim_me = await c.get("/api/v1/auth/me", headers=victim_headers)
        assert victim_me.status_code == 200
        victim_id = victim_me.json()["user_id"]

        suspend = await c.post(
            f"/api/v1/platform/users/{victim_id}/suspend",
            json={"reason": "policy violation"},
            headers={**owner_headers, "X-Assurance-Token": assurance},
        )
        assert suspend.status_code == 200, suspend.text
        assert suspend.json()["status"] == "suspended"

        # The victim's ALREADY-ISSUED token is unchanged and would decode
        # successfully — but the live status check must now deny it.
        denied = await c.get("/api/v1/auth/me", headers=victim_headers)
        assert denied.status_code == 401


@pytest.mark.asyncio
async def test_reactivate_user_restores_access(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        owner_token = await _register(c, _BOOTSTRAP_EMAIL)
        assurance = await _bootstrap_and_assurance(c, owner_token)
        owner_headers = {"Authorization": f"Bearer {owner_token}"}

        victim_token = await _register(c, "victim2@redforge.test")
        victim_headers = {"Authorization": f"Bearer {victim_token}"}
        victim_id = (await c.get("/api/v1/auth/me", headers=victim_headers)).json()["user_id"]

        await c.post(
            f"/api/v1/platform/users/{victim_id}/suspend",
            json={"reason": ""},
            headers={**owner_headers, "X-Assurance-Token": assurance},
        )
        assert (await c.get("/api/v1/auth/me", headers=victim_headers)).status_code == 401

        reactivate = await c.post(
            f"/api/v1/platform/users/{victim_id}/reactivate",
            headers={**owner_headers, "X-Assurance-Token": assurance},
        )
        assert reactivate.status_code == 200
        assert reactivate.json()["status"] == "active"

        restored = await c.get("/api/v1/auth/me", headers=victim_headers)
        assert restored.status_code == 200


@pytest.mark.asyncio
async def test_self_suspension_denied(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        owner_token = await _register(c, _BOOTSTRAP_EMAIL)
        assurance = await _bootstrap_and_assurance(c, owner_token)
        owner_headers = {"Authorization": f"Bearer {owner_token}"}
        owner_id = (await c.get("/api/v1/auth/me", headers=owner_headers)).json()["user_id"]

        resp = await c.post(
            f"/api/v1/platform/users/{owner_id}/suspend",
            json={"reason": "oops"},
            headers={**owner_headers, "X-Assurance-Token": assurance},
        )
        assert resp.status_code == 422


@pytest.mark.asyncio
async def test_suspend_user_requires_step_up(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        owner_token = await _register(c, _BOOTSTRAP_EMAIL)
        await c.post("/api/v1/platform/bootstrap", headers={"Authorization": f"Bearer {owner_token}"})
        owner_headers = {"Authorization": f"Bearer {owner_token}"}

        victim_token = await _register(c, "victim3@redforge.test")
        victim_id = (
            await c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {victim_token}"})
        ).json()["user_id"]

        # No X-Assurance-Token header at all.
        resp = await c.post(
            f"/api/v1/platform/users/{victim_id}/suspend",
            json={"reason": "x"},
            headers=owner_headers,
        )
        assert resp.status_code == 403


# ─── Organization suspension ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_suspend_organization_denies_existing_org_scoped_token(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        owner_token = await _register(c, _BOOTSTRAP_EMAIL)
        assurance = await _bootstrap_and_assurance(c, owner_token)
        owner_headers = {"Authorization": f"Bearer {owner_token}"}

        tenant_token = await _register(c, "tenantowner@redforge.test")
        org_scoped = await _scoped_org_token(c, tenant_token, "gov-test-org")

        orgs = await c.get(
            "/api/v1/auth/organizations", headers={"Authorization": f"Bearer {tenant_token}"}
        )
        org_id = orgs.json()[0]["id"]

        # Sanity: the org-scoped token works on a real tenant-scoped
        # route BEFORE suspension. /targets has no allow_when_suspended
        # exemption (unlike GET /organizations/{id}, which intentionally
        # stays viewable while suspended).
        before = await c.get(
            "/api/v1/targets", headers={"Authorization": f"Bearer {org_scoped}"},
        )
        assert before.status_code == 200

        suspend = await c.post(
            f"/api/v1/platform/organizations/{org_id}/suspend",
            json={"reason": "billing"},
            headers={**owner_headers, "X-Assurance-Token": assurance},
        )
        assert suspend.status_code == 204

        # The already-issued org-scoped token must now be denied on the
        # SAME route it worked on moments ago — organization suspension
        # raises OrganizationInactiveError (422, "not active"), the
        # existing mechanism require_permission already enforces live.
        denied = await c.get(
            "/api/v1/targets", headers={"Authorization": f"Bearer {org_scoped}"},
        )
        assert denied.status_code == 422
        assert "not active" in denied.json()["error"]["message"]


@pytest.mark.asyncio
async def test_reactivate_organization_restores_tenant_operations(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        owner_token = await _register(c, _BOOTSTRAP_EMAIL)
        assurance = await _bootstrap_and_assurance(c, owner_token)
        owner_headers = {"Authorization": f"Bearer {owner_token}"}

        tenant_token = await _register(c, "tenantowner2@redforge.test")
        await _scoped_org_token(c, tenant_token, "gov-test-org-2")
        orgs = await c.get(
            "/api/v1/auth/organizations", headers={"Authorization": f"Bearer {tenant_token}"}
        )
        org_id = orgs.json()[0]["id"]

        await c.post(
            f"/api/v1/platform/organizations/{org_id}/suspend",
            json={"reason": ""},
            headers={**owner_headers, "X-Assurance-Token": assurance},
        )
        reactivate = await c.post(
            f"/api/v1/platform/organizations/{org_id}/reactivate",
            headers={**owner_headers, "X-Assurance-Token": assurance},
        )
        assert reactivate.status_code == 204


# ─── Provider tenant isolation ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tenant_a_provider_invisible_to_tenant_b(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        a_token = await _register(c, "tenanta@redforge.test")
        a_scoped = await _scoped_org_token(c, a_token, "tenant-a-org")
        prov = await c.post(
            "/api/v1/providers",
            json={"name": "tenant-a-provider", "provider_type": "openai", "auth_ref": "KEY_A"},
            headers={"Authorization": f"Bearer {a_scoped}"},
        )
        assert prov.status_code == 201, prov.text
        provider_id = prov.json()["id"]

        b_token = await _register(c, "tenantb@redforge.test")
        b_scoped = await _scoped_org_token(c, b_token, "tenant-b-org")

        # List: tenant B sees zero providers (not tenant A's).
        b_list = await c.get(
            "/api/v1/providers", headers={"Authorization": f"Bearer {b_scoped}"}
        )
        assert b_list.status_code == 200
        assert provider_id not in [p["id"] for p in b_list.json()]

        # Get by ID: 404, not 403 — cannot even confirm existence.
        b_get = await c.get(
            f"/api/v1/providers/{provider_id}", headers={"Authorization": f"Bearer {b_scoped}"}
        )
        assert b_get.status_code == 404

        # Disable: also 404.
        b_disable = await c.patch(
            f"/api/v1/providers/{provider_id}/disable",
            headers={"Authorization": f"Bearer {b_scoped}"},
        )
        assert b_disable.status_code == 404


@pytest.mark.asyncio
async def test_tenant_a_provider_response_contains_no_credential(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        a_token = await _register(c, "tenanta2@redforge.test")
        a_scoped = await _scoped_org_token(c, a_token, "tenant-a2-org")
        sentinel = "sk-SENTINEL_MUST_NOT_APPEAR_IN_RESPONSE"
        prov = await c.post(
            "/api/v1/providers",
            json={
                "name": "tenant-a2-provider", "provider_type": "openai",
                "auth_ref": "SENTINEL_ENV_VAR_NAME",
            },
            headers={"Authorization": f"Bearer {a_scoped}"},
        )
        assert sentinel not in prov.text
        assert prov.json()["organization_id"] is not None
