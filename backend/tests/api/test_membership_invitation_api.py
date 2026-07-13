"""API integration tests for the Membership and Invitation endpoints.

Exercises the full HTTP path (route -> security dependency -> service
-> repository -> response) for the Enterprise Identity Platform sprint,
with particular focus on what the sprint mission called out explicitly:
authorization, RBAC enforcement, tenant isolation, last-owner
protection, self-privilege-escalation prevention, and invitation
token/replay handling — all verified through real HTTP requests, not
direct service calls.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_auth_service,
    get_invitation_service,
    get_membership_service,
    get_organization_service,
    get_token_service,
    get_user_status_service,
)
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.invitations import org_scoped_router as invitations_org_router
from redforge.api.v1.invitations import token_router as invitations_token_router
from redforge.api.v1.memberships import router as memberships_router
from redforge.api.v1.organizations import router as organizations_router
from redforge.application.auth import AuthService
from redforge.application.invitations import InvitationService
from redforge.application.memberships import MembershipService
from redforge.application.organizations import OrganizationService
from redforge.infrastructure.audit.logger import InMemoryAuditLog
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (  # noqa: F401
    InvitationModel,
    MembershipModel,
    OrganizationModel,
    UserModel,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware
from redforge.infrastructure.notifications.logging_notifier import (
    InMemoryInvitationNotifier,
)


@pytest.fixture
async def notifier() -> InMemoryInvitationNotifier:
    return InMemoryInvitationNotifier()


@pytest.fixture
async def audit() -> InMemoryAuditLog:
    return InMemoryAuditLog()


@pytest.fixture
async def app(
    notifier: InMemoryInvitationNotifier, audit: InMemoryAuditLog,
) -> FastAPI:
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    events = InMemoryEventPublisher()
    hasher = Argon2PasswordHasher(time_cost=1, memory_cost=16384, parallelism=1)
    tokens = JWTTokenService(
        secret_key="test-secret-key-that-is-long-enough-32!", access_ttl=3600,
    )
    org_service = OrganizationService(factory, events, audit)
    auth_service = AuthService(factory, hasher, tokens, events)
    membership_service = MembershipService(factory, events, audit)
    invitation_service = InvitationService(factory, events, audit, notifier)

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(organizations_router, prefix="/api/v1")
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(memberships_router, prefix="/api/v1")
    test_app.include_router(invitations_org_router, prefix="/api/v1")
    test_app.include_router(invitations_token_router, prefix="/api/v1")

    test_app.dependency_overrides[get_organization_service] = lambda: org_service
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_auth_service] = lambda: auth_service
    test_app.dependency_overrides[get_token_service] = lambda: tokens
    test_app.dependency_overrides[get_membership_service] = lambda: membership_service
    test_app.dependency_overrides[get_invitation_service] = lambda: invitation_service

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


async def _register(client: AsyncClient, email: str) -> tuple[str, str]:
    """Register a user and return (user_id, unscoped access token)."""
    resp = await client.post("/api/v1/auth/register", json={
        "email": email, "display_name": "Test User", "password": "SecureP@ss123",
    })
    assert resp.status_code == 201, resp.text
    body = resp.json()
    return body["user_id"], body["access_token"]


async def _select(client: AsyncClient, token: str, org_id: str) -> str:
    resp = await client.post(
        f"/api/v1/auth/organizations/{org_id}/select", headers=_auth_headers(token),
    )
    assert resp.status_code == 200, resp.text
    scoped: str = resp.json()["access_token"]
    return scoped


async def _create_org_and_select(
    client: AsyncClient, email: str, name: str, slug: str,
) -> tuple[str, str, str]:
    """Register, create an organization (auto OWNER membership), select
    it, and return (scoped_owner_token, organization_id, owner_user_id)."""
    user_id, unscoped = await _register(client, email)
    create_resp = await client.post(
        "/api/v1/organizations",
        json={"name": name, "slug": slug},
        headers=_auth_headers(unscoped),
    )
    assert create_resp.status_code == 201, create_resp.text
    org_id: str = create_resp.json()["id"]
    scoped = await _select(client, unscoped, org_id)
    return scoped, org_id, user_id


async def _invite_and_accept(
    client: AsyncClient,
    notifier: InMemoryInvitationNotifier,
    owner_token: str,
    org_id: str,
    email: str,
    role: str,
) -> tuple[str, str]:
    """Invite `email` at `role` (as owner_token), register+accept as
    that invitee, and return (invitee_user_id, invitee_unscoped_token)."""
    invite_resp = await client.post(
        f"/api/v1/organizations/{org_id}/invitations",
        json={"email": email, "role": role, "organization_name": "Acme"},
        headers=_auth_headers(owner_token),
    )
    assert invite_resp.status_code == 201, invite_resp.text
    token = notifier.sent[-1].token

    invitee_id, invitee_unscoped = await _register(client, email)
    accept_resp = await client.post(
        "/api/v1/invitations/accept",
        json={"token": token},
        headers=_auth_headers(invitee_unscoped),
    )
    assert accept_resp.status_code == 200, accept_resp.text
    return invitee_id, invitee_unscoped


# ─── Invitation API ─────────────────────────────────────────────────────────


class TestCreateInvitation:
    async def test_owner_can_invite(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "inv-owner@test.com", "Acme", "inv-owner-org",
        )
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/invitations",
            json={"email": "newbie@test.com", "role": "member", "organization_name": "Acme"},
            headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["email"] == "newbie@test.com"
        assert body["status"] == "pending"
        assert len(notifier.sent) == 1

    async def test_no_token_returns_401(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/api/v1/organizations/01HGW2N7HF0000000000000000/invitations",
            json={"email": "x@test.com", "role": "member"},
        )
        assert resp.status_code == 401

    async def test_viewer_cannot_invite(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "viewer-owner@test.com", "Acme", "viewer-inv-org",
        )
        _viewer_id, viewer_unscoped = await _invite_and_accept(
            client, notifier, owner_token, org_id, "viewer1@test.com", "viewer",
        )
        viewer_scoped = await _select(client, viewer_unscoped, org_id)

        resp = await client.post(
            f"/api/v1/organizations/{org_id}/invitations",
            json={"email": "another@test.com", "role": "member"},
            headers=_auth_headers(viewer_scoped),
        )
        assert resp.status_code == 403

    async def test_cross_tenant_invite_denied(self, client: AsyncClient) -> None:
        token_a, org_a, _ = await _create_org_and_select(
            client, "cta-inv-a@test.com", "Org A", "cta-inv-org-a",
        )
        _token_b, org_b, _ = await _create_org_and_select(
            client, "cta-inv-b@test.com", "Org B", "cta-inv-org-b",
        )
        # Org A's token attempting to invite into Org B's URL is rejected
        # before it ever reaches Org B's membership table.
        resp = await client.post(
            f"/api/v1/organizations/{org_b}/invitations",
            json={"email": "x@test.com", "role": "member"},
            headers=_auth_headers(token_a),
        )
        assert resp.status_code == 403
        assert org_a  # sanity: distinct orgs

    async def test_duplicate_pending_invitation_returns_409(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "dup-owner@test.com", "Acme", "dup-inv-org",
        )
        first = await client.post(
            f"/api/v1/organizations/{org_id}/invitations",
            json={"email": "dup@test.com", "role": "member"},
            headers=_auth_headers(owner_token),
        )
        assert first.status_code == 201
        second = await client.post(
            f"/api/v1/organizations/{org_id}/invitations",
            json={"email": "dup@test.com", "role": "member"},
            headers=_auth_headers(owner_token),
        )
        assert second.status_code == 409


class TestListInvitations:
    async def test_lists_org_invitations(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "list-owner@test.com", "Acme", "list-inv-org",
        )
        await client.post(
            f"/api/v1/organizations/{org_id}/invitations",
            json={"email": "listee@test.com", "role": "member"},
            headers=_auth_headers(owner_token),
        )
        resp = await client.get(
            f"/api/v1/organizations/{org_id}/invitations", headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    async def test_cross_tenant_list_denied(self, client: AsyncClient) -> None:
        _token_a, org_a, _ = await _create_org_and_select(
            client, "ctl-a@test.com", "Org A", "ctl-inv-org-a",
        )
        token_b, _org_b, _ = await _create_org_and_select(
            client, "ctl-b@test.com", "Org B", "ctl-inv-org-b",
        )
        resp = await client.get(
            f"/api/v1/organizations/{org_a}/invitations", headers=_auth_headers(token_b),
        )
        assert resp.status_code == 403


class TestAcceptRejectInvitation:
    async def test_accept_creates_active_membership(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "acc-owner@test.com", "Acme", "acc-inv-org",
        )
        invitee_id, invitee_unscoped = await _invite_and_accept(
            client, notifier, owner_token, org_id, "accepter@test.com", "member",
        )
        # The invitee can now select the organization — proof a real,
        # active Membership was created by the HTTP accept call.
        scoped = await _select(client, invitee_unscoped, org_id)
        members_resp = await client.get(
            f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner_token),
        )
        assert members_resp.status_code == 200
        member_ids = {m["user_id"] for m in members_resp.json()}
        assert invitee_id in member_ids
        assert scoped

    async def test_accept_wrong_email_principal_returns_422(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "wrong-owner@test.com", "Acme", "wrong-email-org",
        )
        await client.post(
            f"/api/v1/organizations/{org_id}/invitations",
            json={"email": "intended@test.com", "role": "member"},
            headers=_auth_headers(owner_token),
        )
        token = notifier.sent[-1].token

        _attacker_id, attacker_unscoped = await _register(client, "attacker@test.com")
        resp = await client.post(
            "/api/v1/invitations/accept",
            json={"token": token},
            headers=_auth_headers(attacker_unscoped),
        )
        assert resp.status_code == 422

    async def test_accept_without_auth_returns_401(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "noauth-owner@test.com", "Acme", "noauth-inv-org",
        )
        await client.post(
            f"/api/v1/organizations/{org_id}/invitations",
            json={"email": "someone@test.com", "role": "member"},
            headers=_auth_headers(owner_token),
        )
        token = notifier.sent[-1].token
        resp = await client.post("/api/v1/invitations/accept", json={"token": token})
        assert resp.status_code == 401

    async def test_accept_invalid_token_returns_404(self, client: AsyncClient) -> None:
        _user_id, unscoped = await _register(client, "badtoken@test.com")
        resp = await client.post(
            "/api/v1/invitations/accept",
            json={"token": "not-a-real-token"},
            headers=_auth_headers(unscoped),
        )
        assert resp.status_code == 404

    async def test_replayed_accept_is_idempotent(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "replay-owner@test.com", "Acme", "replay-inv-org",
        )
        await client.post(
            f"/api/v1/organizations/{org_id}/invitations",
            json={"email": "replayer@test.com", "role": "member"},
            headers=_auth_headers(owner_token),
        )
        token = notifier.sent[-1].token
        _invitee_id, invitee_unscoped = await _register(client, "replayer@test.com")

        first = await client.post(
            "/api/v1/invitations/accept",
            json={"token": token},
            headers=_auth_headers(invitee_unscoped),
        )
        assert first.status_code == 200
        second = await client.post(
            "/api/v1/invitations/accept",
            json={"token": token},
            headers=_auth_headers(invitee_unscoped),
        )
        # Same caller, same token, replayed — must not error.
        assert second.status_code == 200
        assert second.json()["status"] == "accepted"

    async def test_reject_requires_no_auth(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "reject-owner@test.com", "Acme", "reject-inv-org",
        )
        await client.post(
            f"/api/v1/organizations/{org_id}/invitations",
            json={"email": "rejecter@test.com", "role": "member"},
            headers=_auth_headers(owner_token),
        )
        token = notifier.sent[-1].token
        resp = await client.post("/api/v1/invitations/reject", json={"token": token})
        assert resp.status_code == 200
        assert resp.json()["status"] == "rejected"


class TestRevokeResendInvitation:
    async def test_owner_can_revoke(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "revoke-owner@test.com", "Acme", "revoke-inv-org",
        )
        create = await client.post(
            f"/api/v1/organizations/{org_id}/invitations",
            json={"email": "revokee@test.com", "role": "member"},
            headers=_auth_headers(owner_token),
        )
        invitation_id = create.json()["id"]
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/invitations/{invitation_id}/revoke",
            headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"

    async def test_member_cannot_revoke(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "revoke2-owner@test.com", "Acme", "revoke2-inv-org",
        )
        create = await client.post(
            f"/api/v1/organizations/{org_id}/invitations",
            json={"email": "revokee2@test.com", "role": "member"},
            headers=_auth_headers(owner_token),
        )
        invitation_id = create.json()["id"]
        _member_id, member_unscoped = await _invite_and_accept(
            client, notifier, owner_token, org_id, "member-revoker@test.com", "member",
        )
        member_scoped = await _select(client, member_unscoped, org_id)
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/invitations/{invitation_id}/revoke",
            headers=_auth_headers(member_scoped),
        )
        assert resp.status_code == 403

    async def test_owner_can_resend(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "resend-owner@test.com", "Acme", "resend-inv-org",
        )
        create = await client.post(
            f"/api/v1/organizations/{org_id}/invitations",
            json={"email": "resendee@test.com", "role": "member"},
            headers=_auth_headers(owner_token),
        )
        invitation_id = create.json()["id"]
        original_token = notifier.sent[-1].token

        resp = await client.post(
            f"/api/v1/organizations/{org_id}/invitations/{invitation_id}/resend",
            headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 200
        assert len(notifier.sent) == 2
        new_token = notifier.sent[-1].token
        assert new_token != original_token

        # The old token must no longer work.
        _invitee_id, invitee_unscoped = await _register(client, "resendee@test.com")
        old_accept = await client.post(
            "/api/v1/invitations/accept",
            json={"token": original_token},
            headers=_auth_headers(invitee_unscoped),
        )
        assert old_accept.status_code == 404


# ─── Membership API ─────────────────────────────────────────────────────────


class TestListMembers:
    async def test_owner_can_list(self, client: AsyncClient) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "list-mem-owner@test.com", "Acme", "list-mem-org",
        )
        resp = await client.get(
            f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 200
        assert len(resp.json()) == 1
        assert resp.json()[0]["role"] == "owner"

    async def test_cross_tenant_list_denied(self, client: AsyncClient) -> None:
        _token_a, org_a, _ = await _create_org_and_select(
            client, "ctm-a@test.com", "Org A", "ctm-mem-org-a",
        )
        token_b, _org_b, _ = await _create_org_and_select(
            client, "ctm-b@test.com", "Org B", "ctm-mem-org-b",
        )
        resp = await client.get(
            f"/api/v1/organizations/{org_a}/members", headers=_auth_headers(token_b),
        )
        assert resp.status_code == 403

    async def test_no_token_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get(
            "/api/v1/organizations/01HGW2N7HF0000000000000000/members",
        )
        assert resp.status_code == 401


class TestChangeRole:
    async def test_owner_can_promote_member(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "promo-owner@test.com", "Acme", "promo-org",
        )
        member_id, _member_unscoped = await _invite_and_accept(
            client, notifier, owner_token, org_id, "promotee@test.com", "member",
        )
        list_resp = await client.get(
            f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner_token),
        )
        membership_id = next(
            m["id"] for m in list_resp.json() if m["user_id"] == member_id
        )
        resp = await client.patch(
            f"/api/v1/organizations/{org_id}/members/{membership_id}/role",
            json={"role": "admin"},
            headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "admin"

    async def test_member_cannot_change_role(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "rbac-owner@test.com", "Acme", "rbac-org",
        )
        member_id, member_unscoped = await _invite_and_accept(
            client, notifier, owner_token, org_id, "rbac-member@test.com", "member",
        )
        member_scoped = await _select(client, member_unscoped, org_id)
        list_resp = await client.get(
            f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner_token),
        )
        membership_id = next(
            m["id"] for m in list_resp.json() if m["user_id"] == member_id
        )
        resp = await client.patch(
            f"/api/v1/organizations/{org_id}/members/{membership_id}/role",
            json={"role": "admin"},
            headers=_auth_headers(member_scoped),
        )
        assert resp.status_code == 403

    async def test_owner_cannot_self_escalate_via_api(
        self, client: AsyncClient,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "self-esc-owner@test.com", "Acme", "self-esc-org",
        )
        list_resp = await client.get(
            f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner_token),
        )
        own_membership_id = list_resp.json()[0]["id"]
        resp = await client.patch(
            f"/api/v1/organizations/{org_id}/members/{own_membership_id}/role",
            json={"role": "admin"},
            headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 422

    async def test_invalid_role_returns_422(self, client: AsyncClient) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "badrole-owner@test.com", "Acme", "badrole-org",
        )
        list_resp = await client.get(
            f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner_token),
        )
        own_membership_id = list_resp.json()[0]["id"]
        resp = await client.patch(
            f"/api/v1/organizations/{org_id}/members/{own_membership_id}/role",
            json={"role": "superadmin"},
            headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 422


class TestSuspendReactivateRemove:
    async def test_owner_can_suspend_and_reactivate(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "susp-owner@test.com", "Acme", "susp-org",
        )
        member_id, _u = await _invite_and_accept(
            client, notifier, owner_token, org_id, "suspendee@test.com", "member",
        )
        list_resp = await client.get(
            f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner_token),
        )
        membership_id = next(
            m["id"] for m in list_resp.json() if m["user_id"] == member_id
        )
        suspend_resp = await client.post(
            f"/api/v1/organizations/{org_id}/members/{membership_id}/suspend",
            headers=_auth_headers(owner_token),
        )
        assert suspend_resp.status_code == 200
        assert suspend_resp.json()["status"] == "suspended"

        reactivate_resp = await client.post(
            f"/api/v1/organizations/{org_id}/members/{membership_id}/reactivate",
            headers=_auth_headers(owner_token),
        )
        assert reactivate_resp.status_code == 200
        assert reactivate_resp.json()["status"] == "active"

    async def test_owner_can_remove_member(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "rm-owner@test.com", "Acme", "rm-org",
        )
        member_id, _u = await _invite_and_accept(
            client, notifier, owner_token, org_id, "removee@test.com", "member",
        )
        list_resp = await client.get(
            f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner_token),
        )
        membership_id = next(
            m["id"] for m in list_resp.json() if m["user_id"] == member_id
        )
        resp = await client.delete(
            f"/api/v1/organizations/{org_id}/members/{membership_id}",
            headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 204

        after = await client.get(
            f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner_token),
        )
        assert member_id not in {m["user_id"] for m in after.json()}

    async def test_cannot_remove_last_owner(self, client: AsyncClient) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "lastowner@test.com", "Acme", "lastowner-org",
        )
        list_resp = await client.get(
            f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner_token),
        )
        own_membership_id = list_resp.json()[0]["id"]
        resp = await client.delete(
            f"/api/v1/organizations/{org_id}/members/{own_membership_id}",
            headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 422

    async def test_member_cannot_suspend_others(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "mem-susp-owner@test.com", "Acme", "mem-susp-org",
        )
        target_id, _u = await _invite_and_accept(
            client, notifier, owner_token, org_id, "target@test.com", "member",
        )
        _actor_id, actor_unscoped = await _invite_and_accept(
            client, notifier, owner_token, org_id, "actor@test.com", "member",
        )
        actor_scoped = await _select(client, actor_unscoped, org_id)
        list_resp = await client.get(
            f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner_token),
        )
        target_membership_id = next(
            m["id"] for m in list_resp.json() if m["user_id"] == target_id
        )
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/members/{target_membership_id}/suspend",
            headers=_auth_headers(actor_scoped),
        )
        assert resp.status_code == 403


class TestLeaveOrganization:
    async def test_member_can_leave(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "leave-owner@test.com", "Acme", "leave-org",
        )
        member_id, member_unscoped = await _invite_and_accept(
            client, notifier, owner_token, org_id, "leaver@test.com", "member",
        )
        member_scoped = await _select(client, member_unscoped, org_id)
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/members/leave",
            headers=_auth_headers(member_scoped),
        )
        assert resp.status_code == 204

        after = await client.get(
            f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner_token),
        )
        assert member_id not in {m["user_id"] for m in after.json()}

    async def test_sole_owner_cannot_leave(self, client: AsyncClient) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "sole-leave@test.com", "Acme", "sole-leave-org",
        )
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/members/leave",
            headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 422


class TestTransferOwnership:
    async def test_owner_can_transfer(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, owner_id = await _create_org_and_select(
            client, "transfer-owner@test.com", "Acme", "transfer-org",
        )
        new_owner_id, _u = await _invite_and_accept(
            client, notifier, owner_token, org_id, "newowner@test.com", "admin",
        )
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/members/transfer-ownership",
            json={"new_owner_user_id": new_owner_id},
            headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "owner"
        assert resp.json()["user_id"] == new_owner_id

        members = await client.get(
            f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner_token),
        )
        roles_by_user = {m["user_id"]: m["role"] for m in members.json()}
        assert roles_by_user[new_owner_id] == "owner"
        assert roles_by_user[owner_id] == "admin"

    async def test_admin_cannot_transfer_ownership_they_lack(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "notowner@test.com", "Acme", "notowner-org",
        )
        admin_id, admin_unscoped = await _invite_and_accept(
            client, notifier, owner_token, org_id, "faketransfer@test.com", "admin",
        )
        admin_scoped = await _select(client, admin_unscoped, org_id)
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/members/transfer-ownership",
            json={"new_owner_user_id": admin_id},
            headers=_auth_headers(admin_scoped),
        )
        assert resp.status_code == 422

    async def test_member_lacking_org_manage_gets_403(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "membertransfer@test.com", "Acme", "membertransfer-org",
        )
        member_id, member_unscoped = await _invite_and_accept(
            client, notifier, owner_token, org_id, "membertransferee@test.com", "member",
        )
        member_scoped = await _select(client, member_unscoped, org_id)
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/members/transfer-ownership",
            json={"new_owner_user_id": member_id},
            headers=_auth_headers(member_scoped),
        )
        assert resp.status_code == 403


class TestOrganizationSuspendViaApi:
    async def test_owner_can_suspend_organization(self, client: AsyncClient) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "orgsuspend@test.com", "Acme", "orgsuspend-org",
        )
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/suspend",
            json={"reason": "billing overdue"},
            headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 200


# ─── Sprint 12 Final Remediation ────────────────────────────────────────────
# Finding 1: OWNER must never be assignable through change_role/invite.
# Finding 2: a suspended organization must be operationally suspended.


class TestOwnerRoleIntegrityViaApi:
    """Every alternate path to OWNER, verified over real HTTP requests."""

    async def test_change_role_to_owner_rejected_at_request_schema(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "ownerint-cr@test.com", "Acme", "ownerint-cr-org",
        )
        target_id, _u = await _invite_and_accept(
            client, notifier, owner_token, org_id, "ownerint-target@test.com", "member",
        )
        list_resp = await client.get(
            f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner_token),
        )
        membership_id = next(
            m["id"] for m in list_resp.json() if m["user_id"] == target_id
        )
        resp = await client.patch(
            f"/api/v1/organizations/{org_id}/members/{membership_id}/role",
            json={"role": "owner"},
            headers=_auth_headers(owner_token),
        )
        # Rejected by the request schema itself (Field pattern excludes
        # "owner") — never even reaches MembershipService.change_role.
        assert resp.status_code == 422

    async def test_invite_with_owner_role_rejected_at_request_schema(
        self, client: AsyncClient,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "ownerint-inv@test.com", "Acme", "ownerint-inv-org",
        )
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/invitations",
            json={"email": "wouldbeowner@test.com", "role": "owner"},
            headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 422

    async def test_only_transfer_ownership_can_grant_owner(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        """Positive control: the one legitimate path still works, proving
        the blocks above are specific to the illegitimate paths, not a
        general OWNER-role malfunction."""
        owner_token, org_id, owner_id = await _create_org_and_select(
            client, "ownerint-legit@test.com", "Acme", "ownerint-legit-org",
        )
        new_owner_id, _u = await _invite_and_accept(
            client, notifier, owner_token, org_id, "ownerint-legit-new@test.com", "admin",
        )
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/members/transfer-ownership",
            json={"new_owner_user_id": new_owner_id},
            headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "owner"
        assert owner_id  # sanity: previous owner still resolvable


class TestOrganizationSuspensionEnforcement:
    """A suspended organization must be operationally suspended across
    every organization-scoped route — enforced centrally in
    api/security.py's require_permission, not per-service."""

    async def test_suspended_org_blocks_membership_list(self, client: AsyncClient) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "susp-mem-list@test.com", "Acme", "susp-mem-list-org",
        )
        await client.post(
            f"/api/v1/organizations/{org_id}/suspend", json={"reason": "policy"},
            headers=_auth_headers(owner_token),
        )
        resp = await client.get(
            f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 422

    async def test_suspended_org_blocks_membership_mutations(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "susp-mem-mut@test.com", "Acme", "susp-mem-mut-org",
        )
        target_id, _u = await _invite_and_accept(
            client, notifier, owner_token, org_id, "susp-mem-target@test.com", "member",
        )
        list_resp = await client.get(
            f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner_token),
        )
        membership_id = next(
            m["id"] for m in list_resp.json() if m["user_id"] == target_id
        )

        await client.post(
            f"/api/v1/organizations/{org_id}/suspend", json={"reason": "policy"},
            headers=_auth_headers(owner_token),
        )

        role_resp = await client.patch(
            f"/api/v1/organizations/{org_id}/members/{membership_id}/role",
            json={"role": "admin"},
            headers=_auth_headers(owner_token),
        )
        assert role_resp.status_code == 422

        suspend_resp = await client.post(
            f"/api/v1/organizations/{org_id}/members/{membership_id}/suspend",
            headers=_auth_headers(owner_token),
        )
        assert suspend_resp.status_code == 422

        remove_resp = await client.delete(
            f"/api/v1/organizations/{org_id}/members/{membership_id}",
            headers=_auth_headers(owner_token),
        )
        assert remove_resp.status_code == 422

    async def test_suspended_org_blocks_ownership_transfer(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "susp-transfer@test.com", "Acme", "susp-transfer-org",
        )
        new_owner_id, _u = await _invite_and_accept(
            client, notifier, owner_token, org_id, "susp-transfer-new@test.com", "admin",
        )
        await client.post(
            f"/api/v1/organizations/{org_id}/suspend", json={"reason": "policy"},
            headers=_auth_headers(owner_token),
        )
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/members/transfer-ownership",
            json={"new_owner_user_id": new_owner_id},
            headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 422

    async def test_suspended_org_blocks_invitation_creation(
        self, client: AsyncClient,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "susp-invite@test.com", "Acme", "susp-invite-org",
        )
        await client.post(
            f"/api/v1/organizations/{org_id}/suspend", json={"reason": "policy"},
            headers=_auth_headers(owner_token),
        )
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/invitations",
            json={"email": "toolate@test.com", "role": "member"},
            headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 422

    async def test_suspended_org_blocks_invitation_acceptance(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        """The invitation is created while the org is still active, then
        the org is suspended before the invitee accepts — acceptance
        must be blocked at accept-time, not just at invite-time, since
        the accept endpoint is org-scoped indirectly through the
        invitation's own organization_id even though the invitee holds
        no token scoped to that org yet.

        InvitationService.accept() is reached via the token-authenticated
        /invitations/accept route, which has no TenantContext (the
        invitee isn't a member yet) — so the central require_permission
        check cannot run for it. This proves acceptance needs its own
        guard, not just the shared one; see the service-level test in
        tests/integration/test_invitation_service.py for the enforcement
        itself.
        """
        owner_token, org_id, _ = await _create_org_and_select(
            client, "susp-accept@test.com", "Acme", "susp-accept-org",
        )
        invite_resp = await client.post(
            f"/api/v1/organizations/{org_id}/invitations",
            json={"email": "toolate-accept@test.com", "role": "member"},
            headers=_auth_headers(owner_token),
        )
        assert invite_resp.status_code == 201
        token = notifier.sent[-1].token

        await client.post(
            f"/api/v1/organizations/{org_id}/suspend", json={"reason": "policy"},
            headers=_auth_headers(owner_token),
        )

        _invitee_id, invitee_unscoped = await _register(client, "toolate-accept@test.com")
        accept_resp = await client.post(
            "/api/v1/invitations/accept",
            json={"token": token},
            headers=_auth_headers(invitee_unscoped),
        )
        assert accept_resp.status_code == 422

    async def test_suspended_org_blocks_organization_administration(
        self, client: AsyncClient,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "susp-admin@test.com", "Acme", "susp-admin-org",
        )
        await client.post(
            f"/api/v1/organizations/{org_id}/suspend", json={"reason": "policy"},
            headers=_auth_headers(owner_token),
        )
        rename_resp = await client.patch(
            f"/api/v1/organizations/{org_id}/rename",
            json={"name": "New Name"},
            headers=_auth_headers(owner_token),
        )
        assert rename_resp.status_code == 422

        deactivate_resp = await client.post(
            f"/api/v1/organizations/{org_id}/deactivate", headers=_auth_headers(owner_token),
        )
        assert deactivate_resp.status_code == 422

    async def test_suspended_org_still_readable_and_reactivatable(
        self, client: AsyncClient,
    ) -> None:
        """The two operations that must keep working on a suspended org:
        viewing it, and reactivating it — otherwise no one could ever
        discover or undo a suspension through the API."""
        owner_token, org_id, _ = await _create_org_and_select(
            client, "susp-readable@test.com", "Acme", "susp-readable-org",
        )
        await client.post(
            f"/api/v1/organizations/{org_id}/suspend", json={"reason": "policy"},
            headers=_auth_headers(owner_token),
        )

        get_resp = await client.get(
            f"/api/v1/organizations/{org_id}", headers=_auth_headers(owner_token),
        )
        assert get_resp.status_code == 200
        assert get_resp.json()["status"] == "suspended"

        activate_resp = await client.post(
            f"/api/v1/organizations/{org_id}/activate", headers=_auth_headers(owner_token),
        )
        assert activate_resp.status_code == 200
        assert activate_resp.json()["status"] == "active"

    async def test_operations_resume_after_reactivation(
        self, client: AsyncClient, notifier: InMemoryInvitationNotifier,
    ) -> None:
        owner_token, org_id, _ = await _create_org_and_select(
            client, "susp-resume@test.com", "Acme", "susp-resume-org",
        )
        await client.post(
            f"/api/v1/organizations/{org_id}/suspend", json={"reason": "policy"},
            headers=_auth_headers(owner_token),
        )
        await client.post(
            f"/api/v1/organizations/{org_id}/activate", headers=_auth_headers(owner_token),
        )

        resp = await client.post(
            f"/api/v1/organizations/{org_id}/invitations",
            json={"email": "postresume@test.com", "role": "member"},
            headers=_auth_headers(owner_token),
        )
        assert resp.status_code == 201

    async def test_deactivated_org_not_blocked_by_suspension_check(
        self, client: AsyncClient,
    ) -> None:
        """Deactivation (INACTIVE) is a distinct lifecycle state from
        suspension — this remediation is scoped to SUSPENDED only, so a
        deactivated org's org:read should not be caught by this check
        (Organization.deactivate/activate's own entity-level invariants
        are a separate, pre-existing concern, not this sprint's scope)."""
        owner_token, org_id, _ = await _create_org_and_select(
            client, "deact-not-susp@test.com", "Acme", "deact-not-susp-org",
        )
        deactivate_resp = await client.post(
            f"/api/v1/organizations/{org_id}/deactivate", headers=_auth_headers(owner_token),
        )
        assert deactivate_resp.status_code == 200

        get_resp = await client.get(
            f"/api/v1/organizations/{org_id}", headers=_auth_headers(owner_token),
        )
        assert get_resp.status_code == 200
        assert get_resp.json()["status"] == "inactive"
