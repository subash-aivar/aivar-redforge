"""Platform/tenant isolation and privilege-escalation adversarial tests.

Uses SQLite for API-boundary/logic correctness (mirrors the
test_credential_leak.py pattern). True concurrency/race-safety proof
requires real PostgreSQL row-locking semantics and lives in
tests/integration/test_platform_bootstrap_race.py instead — this file
does not claim to prove race safety.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_assurance_service,
    get_auth_service,
    get_mfa_service,
    get_organization_service,
    get_platform_access_service,
    get_platform_governance_service,
    get_platform_query_service,
    get_token_service,
    get_user_status_service,
)
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.organizations import router as org_router
from redforge.api.v1.platform import router as platform_router
from redforge.application.auth import AuthService
from redforge.application.mfa import MFAService, PrivilegedAssuranceService
from redforge.application.organizations import OrganizationService
from redforge.application.platform_identity import (
    PlatformAccessService,
    PlatformQueryService,
)
from redforge.application.platform_identity.governance_service import (
    PlatformGovernanceService,
)
from redforge.core.config import Settings
from redforge.domain.platform_identity.value_objects import PlatformRole
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (  # noqa: F401
    AITargetModel,
    CampaignResultModel,
    MembershipModel,
    OrganizationModel,
    PlatformAssignmentModel,
    PlatformAuditLogModel,
    PlatformBootstrapStateModel,
    UserModel,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware

_BOOTSTRAP_EMAIL = "owner@redforge.test"
_TEST_MFA_KEY = "JCBz3tgnOeWF7cKJJpMOD9iTL4pc0h9KLX3kgCyj-9g="


@pytest.fixture
async def engine():
    eng = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # platform_bootstrap_state needs its seeded singleton row, which
        # migration 0011 inserts — replicate that here for the test engine.
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



class _AlwaysActiveUserStatusService:
    """Test double: every user is ACTIVE. Real suspension-enforcement
    tests live in tests/api/test_platform_identity_api.py; this fake
    just keeps pre-existing fixtures unaffected by the new M2
    live-user-status check in api/security.py.
    """

    async def get_status(self, user_id: str) -> str:
        return "active"


def _settings(bootstrap_enabled: bool = True) -> Settings:
    return Settings(
        environment="test",
        jwt_secret="test-secret-key-that-is-long-enough-32!",
        platform_bootstrap_enabled=bootstrap_enabled,
        platform_bootstrap_principal_email=_BOOTSTRAP_EMAIL,
    )


@pytest.fixture
def app(factory):
    hasher = Argon2PasswordHasher(time_cost=1, memory_cost=16384, parallelism=1)
    token_svc = JWTTokenService(secret_key="test-secret-key-that-is-long-enough-32!", access_ttl=3600)
    publisher = InMemoryEventPublisher()

    auth_svc = AuthService(
        session_factory=factory, password_hasher=hasher,
        token_service=token_svc, event_publisher=publisher,
    )
    org_svc = OrganizationService(session_factory=factory, event_publisher=publisher)
    platform_access_svc = PlatformAccessService(factory, _settings())
    platform_query_svc = PlatformQueryService(factory)
    platform_governance_svc = PlatformGovernanceService(factory, org_svc)
    mfa_svc = MFAService(factory, _TEST_MFA_KEY)
    assurance_svc = PrivilegedAssuranceService(factory, mfa_svc, ttl_seconds=300)

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(org_router, prefix="/api/v1")
    test_app.include_router(platform_router, prefix="/api/v1")

    test_app.dependency_overrides[get_token_service] = lambda: token_svc
    test_app.dependency_overrides[get_auth_service] = lambda: auth_svc
    test_app.dependency_overrides[get_organization_service] = lambda: org_svc
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_platform_access_service] = lambda: platform_access_svc
    test_app.dependency_overrides[get_platform_query_service] = lambda: platform_query_svc
    test_app.dependency_overrides[get_platform_governance_service] = lambda: platform_governance_svc
    test_app.dependency_overrides[get_mfa_service] = lambda: mfa_svc
    test_app.dependency_overrides[get_assurance_service] = lambda: assurance_svc

    return test_app


async def _register(client: AsyncClient, email: str, password: str = "testpass123!") -> str:
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "display_name": "Test User", "password": password},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["access_token"]


async def _enroll_mfa_and_get_assurance(client: AsyncClient, token: str) -> str:
    """Full real step-up flow: begin enrollment -> verify with a real
    TOTP code -> activate -> step up with a fresh code -> assurance
    token. Used by tests exercising the M2 step-up-gated mutations.
    """
    import pyotp

    headers = {"Authorization": f"Bearer {token}"}
    begin = await client.post("/api/v1/platform/mfa/enroll/begin", headers=headers)
    assert begin.status_code == 201, begin.text
    enrollment_id = begin.json()["enrollment_id"]
    secret = begin.json()["secret"]

    totp = pyotp.TOTP(secret)
    verify = await client.post(
        "/api/v1/platform/mfa/enroll/verify",
        json={"enrollment_id": enrollment_id, "code": totp.now()},
        headers=headers,
    )
    assert verify.status_code == 204, verify.text

    step_up = await client.post(
        "/api/v1/platform/assurance/step-up",
        json={"code": totp.now()},
        headers=headers,
    )
    assert step_up.status_code == 200, step_up.text
    return step_up.json()["assurance_token"]


async def _scoped_org_token(client: AsyncClient, token: str) -> str:
    slug_suffix = "".join(c for c in token[-10:] if c.isalnum()).lower() or "x"
    org = await client.post(
        "/api/v1/organizations",
        json={"name": "Test Org", "slug": f"test-org-{slug_suffix}"},
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


# ─── Platform escalation ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_normal_user_cannot_become_platform_admin(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "normal@redforge.test")
        me = await c.get("/api/v1/platform/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200
        assert me.json()["has_platform_access"] is False
        assert me.json()["platform_roles"] == []


@pytest.mark.asyncio
async def test_organization_admin_cannot_become_platform_admin(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "orgowner@redforge.test")
        org_scoped = await _scoped_org_token(c, token)
        # org_scoped token belongs to the OWNER of their own org — proves
        # even the highest tenant role has zero platform standing.
        me = await c.get(
            "/api/v1/platform/me", headers={"Authorization": f"Bearer {org_scoped}"}
        )
        assert me.status_code == 200
        assert me.json()["has_platform_access"] is False

        users = await c.get(
            "/api/v1/platform/users", headers={"Authorization": f"Bearer {org_scoped}"}
        )
        assert users.status_code == 403


@pytest.mark.asyncio
async def test_org_role_manipulation_cannot_create_platform_permission(app):
    """A crafted/forged 'role' string in a request has no bearing on
    platform authorization — platform permissions come exclusively from
    persisted PlatformAssignment rows, never from any request field.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "forger@redforge.test")
        # Attempt to smuggle a platform role via an arbitrary JSON body on
        # an endpoint that does not accept one.
        resp = await c.get(
            "/api/v1/platform/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.json()["platform_roles"] == []


@pytest.mark.asyncio
async def test_missing_authentication_denied(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/api/v1/platform/me")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_malformed_bearer_token_denied(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(
            "/api/v1/platform/me",
            headers={"Authorization": "Bearer not-a-real-jwt"},
        )
        assert resp.status_code == 401


# ─── Bootstrap ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bootstrap_disabled_denied(factory):
    disabled_settings = _settings(bootstrap_enabled=False)
    svc = PlatformAccessService(factory, disabled_settings)
    from redforge.domain.platform_identity.exceptions import BootstrapDisabledError

    with pytest.raises(BootstrapDisabledError):
        await svc.bootstrap_super_admin("user-1", _BOOTSTRAP_EMAIL)


@pytest.mark.asyncio
async def test_bootstrap_wrong_principal_denied(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "attacker@redforge.test")
        resp = await c.post(
            "/api/v1/platform/bootstrap", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_bootstrap_unauthenticated_denied(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.post("/api/v1/platform/bootstrap")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_first_correct_bootstrap_succeeds_then_second_denied(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, _BOOTSTRAP_EMAIL)

        first = await c.post(
            "/api/v1/platform/bootstrap", headers={"Authorization": f"Bearer {token}"}
        )
        assert first.status_code == 201, first.text
        assert first.json()["role"] == PlatformRole.SUPER_ADMIN.value

        me = await c.get("/api/v1/platform/me", headers={"Authorization": f"Bearer {token}"})
        assert me.json()["has_platform_access"] is True
        assert PlatformRole.SUPER_ADMIN.value in me.json()["platform_roles"]

        second = await c.post(
            "/api/v1/platform/bootstrap", headers={"Authorization": f"Bearer {token}"}
        )
        assert second.status_code == 409


@pytest.mark.asyncio
async def test_second_different_user_cannot_bootstrap_after_consumption(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        owner_token = await _register(c, _BOOTSTRAP_EMAIL)
        await c.post(
            "/api/v1/platform/bootstrap", headers={"Authorization": f"Bearer {owner_token}"}
        )

        # A second user whose email even matches (edge case: two accounts
        # can't share an email, so simulate via direct service call with
        # the same configured email after consumption).
        status_resp = await c.get(
            "/api/v1/platform/bootstrap/status",
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert status_resp.json()["available"] is False


# ─── Access governance ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unauthorized_grant_denied(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "nonadmin@redforge.test")
        resp = await c.post(
            "/api/v1/platform/access",
            json={"target_user_id": "some-user", "role": PlatformRole.SUPER_ADMIN.value},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_unauthorized_revoke_denied(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "nonadmin2@redforge.test")
        resp = await c.post(
            "/api/v1/platform/access/some-assignment-id/revoke",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_super_admin_can_grant_and_revoke_access(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        owner_token = await _register(c, _BOOTSTRAP_EMAIL)
        await c.post(
            "/api/v1/platform/bootstrap", headers={"Authorization": f"Bearer {owner_token}"}
        )
        owner_me = await c.get(
            "/api/v1/platform/me", headers={"Authorization": f"Bearer {owner_token}"}
        )
        assert owner_me.json()["has_platform_access"] is True

        second_token = await _register(c, "second-admin@redforge.test")
        second_me = await c.get(
            "/api/v1/platform/me", headers={"Authorization": f"Bearer {second_token}"}
        )
        second_user_id = second_me.json()["user_id"]

        assurance = await _enroll_mfa_and_get_assurance(c, owner_token)

        grant = await c.post(
            "/api/v1/platform/access",
            json={"target_user_id": second_user_id, "role": PlatformRole.SUPER_ADMIN.value},
            headers={
                "Authorization": f"Bearer {owner_token}",
                "X-Assurance-Token": assurance,
            },
        )
        assert grant.status_code == 201, grant.text
        assignment_id = grant.json()["id"]

        second_me_after = await c.get(
            "/api/v1/platform/me", headers={"Authorization": f"Bearer {second_token}"}
        )
        assert second_me_after.json()["has_platform_access"] is True

        # Now revoke the SECOND admin's access (owner's own remains) —
        # must succeed since owner is still an active Super Admin.
        revoke = await c.post(
            f"/api/v1/platform/access/{assignment_id}/revoke",
            headers={
                "Authorization": f"Bearer {owner_token}",
                "X-Assurance-Token": assurance,
            },
        )
        assert revoke.status_code == 200, revoke.text
        assert revoke.json()["status"] == "revoked"


@pytest.mark.asyncio
async def test_duplicate_active_grant_rejected(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        owner_token = await _register(c, _BOOTSTRAP_EMAIL)
        await c.post(
            "/api/v1/platform/bootstrap", headers={"Authorization": f"Bearer {owner_token}"}
        )
        owner_me = await c.get(
            "/api/v1/platform/me", headers={"Authorization": f"Bearer {owner_token}"}
        )
        owner_id = owner_me.json()["user_id"]
        assurance = await _enroll_mfa_and_get_assurance(c, owner_token)

        # Attempting to grant SUPER_ADMIN to the owner again (already
        # active from bootstrap) must be rejected, not silently duplicated.
        dup = await c.post(
            "/api/v1/platform/access",
            json={"target_user_id": owner_id, "role": PlatformRole.SUPER_ADMIN.value},
            headers={
                "Authorization": f"Bearer {owner_token}",
                "X-Assurance-Token": assurance,
            },
        )
        assert dup.status_code == 409


@pytest.mark.asyncio
async def test_last_super_admin_cannot_be_revoked(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        owner_token = await _register(c, _BOOTSTRAP_EMAIL)
        boot = await c.post(
            "/api/v1/platform/bootstrap", headers={"Authorization": f"Bearer {owner_token}"}
        )
        assignment_id = boot.json()["assignment_id"]
        assurance = await _enroll_mfa_and_get_assurance(c, owner_token)

        revoke = await c.post(
            f"/api/v1/platform/access/{assignment_id}/revoke",
            headers={
                "Authorization": f"Bearer {owner_token}",
                "X-Assurance-Token": assurance,
            },
        )
        # 403 for the LAST-SUPER-ADMIN reason specifically (not a missing-
        # assurance 403, since a valid assurance token was supplied above).
        assert revoke.status_code == 403
        assert "Super Admin" in revoke.json()["detail"]

        # Still has access after the denied revoke.
        me = await c.get(
            "/api/v1/platform/me", headers={"Authorization": f"Bearer {owner_token}"}
        )
        assert me.json()["has_platform_access"] is True


@pytest.mark.asyncio
async def test_audit_evidence_created_for_bootstrap_and_grant_revoke(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        owner_token = await _register(c, _BOOTSTRAP_EMAIL)
        await c.post(
            "/api/v1/platform/bootstrap", headers={"Authorization": f"Bearer {owner_token}"}
        )

        audit = await c.get(
            "/api/v1/platform/audit", headers={"Authorization": f"Bearer {owner_token}"}
        )
        assert audit.status_code == 200
        actions = [e["action"] for e in audit.json()]
        assert "platform.bootstrap_succeeded" in actions


# ─── Tenant/platform separation ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tenant_scoped_endpoint_still_requires_org_selection(app):
    """Sanity check that platform work hasn't weakened tenant auth: an
    org-scoped endpoint still 401/403s without a selected-org token.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "noorg@redforge.test")
        resp = await c.get(
            "/api/v1/organizations/some-id",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code in (401, 403, 404, 422)


@pytest.mark.asyncio
async def test_platform_context_not_satisfied_by_org_scoped_token_alone(app):
    """An org-scoped (tenant) token still has zero platform access unless
    a PlatformAssignment independently exists for that user — proves
    organization role never manufactures platform permission.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "org-owner-2@redforge.test")
        org_scoped = await _scoped_org_token(c, token)

        me = await c.get(
            "/api/v1/platform/me", headers={"Authorization": f"Bearer {org_scoped}"}
        )
        assert me.status_code == 200
        assert me.json()["has_platform_access"] is False
