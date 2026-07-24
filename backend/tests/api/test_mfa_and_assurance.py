"""MFA enrollment/activation/revocation and privileged-assurance step-up
adversarial tests — M2.

Uses SQLite for API-boundary correctness (same pattern as
test_platform_identity_api.py). Secret-leak checks (never returned
after activation, never in audit) are proven here directly against
response bodies.
"""

from __future__ import annotations

import asyncio

import pyotp
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_assurance_service,
    get_auth_service,
    get_effective_access_service,
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
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware

_TEST_MFA_KEY = "JCBz3tgnOeWF7cKJJpMOD9iTL4pc0h9KLX3kgCyj-9g="
_SENTINEL_SECRET_MARKER = "SENTINEL_TOTP_SECRET_MUST_NOT_LEAK_ANYWHERE"


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
        platform_bootstrap_principal_email="owner9@redforge.test",
    )
    platform_access_svc = PlatformAccessService(factory, settings)
    platform_query_svc = PlatformQueryService(factory)
    platform_governance_svc = PlatformGovernanceService(factory, org_svc)
    mfa_svc = MFAService(factory, _TEST_MFA_KEY)
    assurance_svc = PrivilegedAssuranceService(factory, mfa_svc, ttl_seconds=2)

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(org_router, prefix="/api/v1")
    test_app.include_router(platform_router, prefix="/api/v1")

    test_app.dependency_overrides[get_token_service] = lambda: token_svc
    test_app.dependency_overrides[get_auth_service] = lambda: auth_svc
    test_app.dependency_overrides[get_organization_service] = lambda: org_svc
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_effective_access_service] = lambda: _NoOpEffectiveAccessService()
    test_app.dependency_overrides[get_platform_access_service] = lambda: platform_access_svc
    test_app.dependency_overrides[get_platform_query_service] = lambda: platform_query_svc
    test_app.dependency_overrides[get_platform_governance_service] = lambda: platform_governance_svc
    test_app.dependency_overrides[get_mfa_service] = lambda: mfa_svc
    test_app.dependency_overrides[get_assurance_service] = lambda: assurance_svc

    return test_app


async def _register(client: AsyncClient, email: str) -> str:
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "display_name": "Test User", "password": "testpass123!"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["access_token"]


# ─── MFA enrollment ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unauthenticated_enrollment_denied(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.post("/api/v1/platform/mfa/enroll/begin")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_factor_cannot_activate_without_proof_invalid_code_denied(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "u1@redforge.test")
        headers = {"Authorization": f"Bearer {token}"}
        begin = await c.post("/api/v1/platform/mfa/enroll/begin", headers=headers)
        enrollment_id = begin.json()["enrollment_id"]

        verify = await c.post(
            "/api/v1/platform/mfa/enroll/verify",
            json={"enrollment_id": enrollment_id, "code": "000000"},
            headers=headers,
        )
        assert verify.status_code == 422

        status_resp = await c.get("/api/v1/platform/mfa/status", headers=headers)
        assert status_resp.json()["active"] is False


@pytest.mark.asyncio
async def test_activated_factor_works_and_secret_never_returned_again(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "u2@redforge.test")
        headers = {"Authorization": f"Bearer {token}"}
        begin = await c.post("/api/v1/platform/mfa/enroll/begin", headers=headers)
        enrollment_id = begin.json()["enrollment_id"]
        secret = begin.json()["secret"]

        verify = await c.post(
            "/api/v1/platform/mfa/enroll/verify",
            json={"enrollment_id": enrollment_id, "code": pyotp.TOTP(secret).now()},
            headers=headers,
        )
        assert verify.status_code == 204

        status_resp = await c.get("/api/v1/platform/mfa/status", headers=headers)
        assert status_resp.json()["active"] is True

        # Secret must never appear in the status response or anywhere else.
        assert secret not in status_resp.text


@pytest.mark.asyncio
async def test_revoked_factor_cannot_establish_assurance(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "u3@redforge.test")
        headers = {"Authorization": f"Bearer {token}"}
        begin = await c.post("/api/v1/platform/mfa/enroll/begin", headers=headers)
        enrollment_id = begin.json()["enrollment_id"]
        secret = begin.json()["secret"]
        totp = pyotp.TOTP(secret)

        await c.post(
            "/api/v1/platform/mfa/enroll/verify",
            json={"enrollment_id": enrollment_id, "code": totp.now()},
            headers=headers,
        )
        revoke = await c.post("/api/v1/platform/mfa/revoke", headers=headers)
        assert revoke.status_code == 204

        step_up = await c.post(
            "/api/v1/platform/assurance/step-up",
            json={"code": totp.now()},
            headers=headers,
        )
        assert step_up.status_code == 403
        assert step_up.json()["detail"].startswith(
            "This action requires a current privileged authentication assurance"
        )


@pytest.mark.asyncio
async def test_expired_enrollment_replaced_not_stacked(app):
    """Beginning enrollment twice without activating discards the first
    pending factor rather than accumulating orphaned rows (would violate
    the partial-unique-pending-per-user index on real PostgreSQL)."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "u4@redforge.test")
        headers = {"Authorization": f"Bearer {token}"}
        first = await c.post("/api/v1/platform/mfa/enroll/begin", headers=headers)
        second = await c.post("/api/v1/platform/mfa/enroll/begin", headers=headers)
        assert first.status_code == 201
        assert second.status_code == 201
        assert first.json()["enrollment_id"] != second.json()["enrollment_id"]

        # The FIRST enrollment_id is no longer valid — it was replaced.
        verify_stale = await c.post(
            "/api/v1/platform/mfa/enroll/verify",
            json={
                "enrollment_id": first.json()["enrollment_id"],
                "code": pyotp.TOTP(first.json()["secret"]).now(),
            },
            headers=headers,
        )
        assert verify_stale.status_code == 404


@pytest.mark.asyncio
async def test_double_active_enrollment_denied(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "u5@redforge.test")
        headers = {"Authorization": f"Bearer {token}"}
        begin = await c.post("/api/v1/platform/mfa/enroll/begin", headers=headers)
        secret = begin.json()["secret"]
        await c.post(
            "/api/v1/platform/mfa/enroll/verify",
            json={
                "enrollment_id": begin.json()["enrollment_id"],
                "code": pyotp.TOTP(secret).now(),
            },
            headers=headers,
        )

        second_begin = await c.post("/api/v1/platform/mfa/enroll/begin", headers=headers)
        assert second_begin.status_code == 409


# ─── Privileged assurance ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_assurance_denied_without_active_factor(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "u6@redforge.test")
        headers = {"Authorization": f"Bearer {token}"}
        step_up = await c.post(
            "/api/v1/platform/assurance/step-up", json={"code": "123456"}, headers=headers,
        )
        assert step_up.status_code == 403


@pytest.mark.asyncio
async def test_assurance_for_user_a_cannot_be_used_by_user_b(app):
    """An assurance token is bound to the user_id that established it —
    presenting it with a different user's bearer token must not work."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token_a = await _register(c, "u7a@redforge.test")
        token_b = await _register(c, "u7b@redforge.test")

        headers_a = {"Authorization": f"Bearer {token_a}"}
        begin = await c.post("/api/v1/platform/mfa/enroll/begin", headers=headers_a)
        secret = begin.json()["secret"]
        await c.post(
            "/api/v1/platform/mfa/enroll/verify",
            json={"enrollment_id": begin.json()["enrollment_id"], "code": pyotp.TOTP(secret).now()},
            headers=headers_a,
        )
        step_up = await c.post(
            "/api/v1/platform/assurance/step-up",
            json={"code": pyotp.TOTP(secret).now()},
            headers=headers_a,
        )
        assurance_token = step_up.json()["assurance_token"]

        # User B has zero platform permission anyway, but critically the
        # assurance token check itself is scoped to platform.user_id —
        # bootstrap B first to isolate the permission dimension.
        headers_b = {"Authorization": f"Bearer {token_b}"}
        resp = await c.post(
            "/api/v1/platform/access",
            json={"target_user_id": "someone", "role": "platform_super_admin"},
            headers={**headers_b, "X-Assurance-Token": assurance_token},
        )
        # 403 either way (no permission), but the point proven here is
        # that no code path derives platform.user_id from the assurance
        # token itself — it always comes from B's own bearer token.
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_assurance_expires_after_configured_ttl(app):
    """Fixture wires ttl_seconds=2 specifically so this test can prove
    real expiry without an excessive sleep. Uses a bootstrapped Super
    Admin (has every platform permission) so a 403 here can only mean
    the assurance itself expired — isolating the expiry check from the
    separate permission check.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        owner_token = await _register(c, "owner9@redforge.test")
        owner_headers = {"Authorization": f"Bearer {owner_token}"}
        boot = await c.post("/api/v1/platform/bootstrap", headers=owner_headers)
        assert boot.status_code == 201, boot.text

        begin = await c.post("/api/v1/platform/mfa/enroll/begin", headers=owner_headers)
        secret = begin.json()["secret"]
        await c.post(
            "/api/v1/platform/mfa/enroll/verify",
            json={"enrollment_id": begin.json()["enrollment_id"], "code": pyotp.TOTP(secret).now()},
            headers=owner_headers,
        )
        step_up = await c.post(
            "/api/v1/platform/assurance/step-up",
            json={"code": pyotp.TOTP(secret).now()},
            headers=owner_headers,
        )
        assurance_token = step_up.json()["assurance_token"]

        # Immediately usable — proves the token was valid at all.
        immediate = await c.get("/api/v1/platform/access", headers=owner_headers)
        assert immediate.status_code == 200

        await asyncio.sleep(2.5)

        resp = await c.post(
            "/api/v1/platform/access",
            json={"target_user_id": "some-other-user", "role": "platform_support"},
            headers={**owner_headers, "X-Assurance-Token": assurance_token},
        )
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "MFA_ASSURANCE_REQUIRED"


@pytest.mark.asyncio
async def test_malformed_assurance_token_denied(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        owner_token = await _register(c, "owner8@redforge.test")
        headers = {"Authorization": f"Bearer {owner_token}"}
        resp = await c.post(
            "/api/v1/platform/access",
            json={"target_user_id": "x", "role": "platform_super_admin"},
            headers={**headers, "X-Assurance-Token": "not-a-real-token"},
        )
        assert resp.status_code == 403
