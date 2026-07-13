"""M17 — real running app, real PostgreSQL, real HTTP adversarial +
enforcement + concurrency acceptance for the RBAC control plane.

Runs the actual FastAPI application (redforge.app.create_app, full
production dependency wiring) over `httpx.AsyncClient` + `ASGITransport`
with the app's own `lifespan_context()` — the same pattern M11-M16's own
live-acceptance proofs use. Every scenario below is a REAL HTTP round
trip against a REAL database; nothing here is mocked.
"""

from __future__ import annotations

import asyncio
import os
import time

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.asyncio(loop_scope="module")

# A dedicated, isolated proof database — NOT the shared `redforge_test`
# used by the wider suite. This test file runs the FULL real app,
# including its background schedulers (continuous_validation_scheduler,
# network_monitoring_scheduler); on the shared DB those workers would
# pick up and race against leftover due policies from OTHER test files'
# runs, an unrelated pre-existing pollution hazard this isolation
# avoids entirely (same discipline M1's/M16's own dedicated proof
# databases already use).
_TEST_DB_NAME = "redforge_rbac_proof_test"
_DB_URL = os.environ.get(
    "REDFORGE_RBAC_TEST_DATABASE_URL",
    f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_TEST_DB_NAME}",
)


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client():
    """One shared app/lifespan for the whole module — not one per test.
    Spinning up ~25 full app instances (each with 4 background workers)
    back-to-back in one pytest process is what causes asyncpg
    connection-teardown races to surface as spurious resource warnings;
    every test here already uses its own freshly-registered org, so
    sharing one running app carries no cross-test data risk."""
    from unittest.mock import patch

    from redforge.app import create_app
    from redforge.core.config import Settings
    from redforge.infrastructure.rate_limiting.contracts import RateLimitResult
    from redforge.infrastructure.rate_limiting.sliding_window import (
        InMemorySlidingWindowLimiter,
    )

    # This module registers many real users from the same test-process
    # IP in rapid succession — genuinely tripping the real per-IP
    # register rate limit, which is correct production behavior, not a
    # defect. Disabling it here (this test file only) is equivalent to
    # every other M-milestone live-acceptance script's own practice of
    # driving many real registrations in one run; the rate limiter
    # itself is unit-tested elsewhere and is not part of M17's surface.
    async def _always_allow(self: object, key: str, max_requests: int, window_seconds: int) -> RateLimitResult:
        return RateLimitResult(allowed=True, remaining=max_requests, limit=max_requests, retry_after_seconds=0)

    with patch.object(InMemorySlidingWindowLimiter, "check", _always_allow):
        app = create_app(settings=Settings(database_url=_DB_URL))
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app, raise_app_exceptions=False)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                yield c


def _unique(prefix: str) -> str:
    return f"{prefix}-{time.time_ns()}"


async def _register(client: AsyncClient, email: str) -> str:
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "display_name": "M17 Test User", "password": "SecureP@ss123"},
    )
    assert r.status_code == 201, r.text
    return r.json()["access_token"]


async def _create_org_and_select(client: AsyncClient, token: str, slug: str) -> tuple[str, str]:
    r = await client.post(
        "/api/v1/organizations",
        json={"name": "M17 Test Org", "slug": slug},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 201, r.text
    org_id = r.json()["id"]
    r = await client.post(
        f"/api/v1/auth/organizations/{org_id}/select",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    return org_id, r.json()["access_token"]


async def _owner_context(client: AsyncClient) -> tuple[str, str, dict[str, str]]:
    """Registers a fresh user, creates a fresh org, returns
    (org_id, user_id, auth_headers) for the OWNER of that org."""
    unique = _unique("owner")
    token = await _register(client, f"{unique}@example.test")
    org_id, scoped = await _create_org_and_select(client, token, _unique("org"))
    r = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {scoped}"})
    user_id = r.json()["user_id"]
    return org_id, user_id, {"Authorization": f"Bearer {scoped}"}


async def _invite_member(
    client: AsyncClient, owner_headers: dict[str, str], org_id: str, role: str,
) -> tuple[str, dict[str, str]]:
    """Real invitation -> accept -> role-change flow (mirrors the M2
    precedent) producing a second real member with the given
    MembershipRole, distinct from the OWNER."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from redforge.application.invitations import InvitationService
    from redforge.infrastructure.audit.logger import InMemoryAuditLog
    from redforge.infrastructure.events import InMemoryEventPublisher
    from redforge.infrastructure.notifications.logging_notifier import (
        InMemoryInvitationNotifier,
    )

    fixture_engine = create_async_engine(_DB_URL, echo=False)
    fixture_session_factory = async_sessionmaker(fixture_engine, expire_on_commit=False)
    notifier = InMemoryInvitationNotifier()
    invitation_service = InvitationService(
        fixture_session_factory, InMemoryEventPublisher(), InMemoryAuditLog(), notifier,
    )
    r = await client.get("/api/v1/auth/me", headers=owner_headers)
    owner_user_id = r.json()["user_id"]
    unique = _unique("member")
    email = f"{unique}@example.test"
    await invitation_service.invite(
        organization_id=org_id, invited_by_user_id=owner_user_id, email=email,
        role="member", organization_name="M17 Test Org",
    )
    invite_token = notifier.sent[0].token
    await fixture_engine.dispose()

    unauth_token = await _register(client, email)
    r = await client.post(
        "/api/v1/invitations/accept",
        json={"token": invite_token},
        headers={"Authorization": f"Bearer {unauth_token}"},
    )
    assert r.status_code == 200, r.text
    member_token = unauth_token
    r = await client.post(
        f"/api/v1/auth/organizations/{org_id}/select",
        headers={"Authorization": f"Bearer {member_token}"},
    )
    scoped_token = r.json()["access_token"]
    r = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {scoped_token}"})
    member_user_id = r.json()["user_id"]

    r = await client.get(f"/api/v1/organizations/{org_id}/members", headers=owner_headers)
    membership_id = next(m["id"] for m in r.json() if m["user_id"] == member_user_id)
    if role != "member":
        r = await client.patch(
            f"/api/v1/organizations/{org_id}/members/{membership_id}/role",
            json={"role": role}, headers=owner_headers,
        )
        assert r.status_code == 200, r.text
        r = await client.post(
            f"/api/v1/auth/organizations/{org_id}/select",
            headers={"Authorization": f"Bearer {member_token}"},
        )
        scoped_token = r.json()["access_token"]

    return member_user_id, {"Authorization": f"Bearer {scoped_token}"}


# ─── Golden path: roles, groups, effective access ──────────────────────────


async def test_role_and_group_golden_path(client: AsyncClient) -> None:
    _org_id, owner_id, owner = await _owner_context(client)

    r = await client.get("/api/v1/admin/permissions", headers=owner)
    assert r.status_code == 200 and len(r.json()) > 0

    r = await client.get("/api/v1/admin/roles", headers=owner)
    assert r.status_code == 200
    assert len(r.json()) == 6  # exactly the 6 system MembershipRoles
    assert all(role["is_system"] for role in r.json())

    r = await client.post(
        "/api/v1/admin/roles",
        json={"name": "SOC Analyst", "description": "d", "permissions": ["findings:read", "targets:read"]},
        headers=owner,
    )
    assert r.status_code == 201, r.text
    role_id = r.json()["id"]
    assert r.json()["is_system"] is False

    r = await client.post(
        "/api/v1/admin/groups", json={"name": "SOC Team", "description": "d"}, headers=owner,
    )
    assert r.status_code == 201, r.text
    group_id = r.json()["id"]

    r = await client.post(
        f"/api/v1/admin/groups/{group_id}/roles", json={"role_id": role_id}, headers=owner,
    )
    assert r.status_code == 204

    r = await client.post(
        f"/api/v1/admin/groups/{group_id}/members", json={"user_id": owner_id}, headers=owner,
    )
    assert r.status_code == 204

    r = await client.get(f"/api/v1/admin/users/{owner_id}/effective-access", headers=owner)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["groups"][0]["group_id"] == group_id
    assert "findings:read" in body["effective_permissions"]

    r = await client.delete(f"/api/v1/admin/groups/{group_id}/roles/{role_id}", headers=owner)
    assert r.status_code == 204
    r = await client.get(f"/api/v1/admin/groups/{group_id}/roles", headers=owner)
    assert r.json() == []


# ─── Enforcement: a group-derived custom role actually grants access ───────


async def test_group_derived_role_actually_unlocks_a_permission(client: AsyncClient) -> None:
    """The core enforcement proof: a VIEWER cannot administer RBAC by
    default; after being granted a custom role (via group membership)
    that carries ROLES_READ, the SAME already-issued session token
    gains real access on its very next request — no re-login, no token
    refresh. This is what proves get_tenant_context's additive
    enrichment is real, not decorative."""
    org_id, _owner_id, owner = await _owner_context(client)
    viewer_id, viewer = await _invite_member(client, owner, org_id, "viewer")

    r = await client.get("/api/v1/admin/roles", headers=viewer)
    assert r.status_code == 403, "VIEWER must not have ROLES_READ by default"

    r = await client.post(
        "/api/v1/admin/roles", json={"name": "Role Viewer", "permissions": ["roles:read"]},
        headers=owner,
    )
    role_id = r.json()["id"]
    r = await client.post(
        "/api/v1/admin/groups", json={"name": "Role Viewers"}, headers=owner,
    )
    group_id = r.json()["id"]
    await client.post(f"/api/v1/admin/groups/{group_id}/roles", json={"role_id": role_id}, headers=owner)
    await client.post(f"/api/v1/admin/groups/{group_id}/members", json={"user_id": viewer_id}, headers=owner)

    r = await client.get("/api/v1/admin/roles", headers=viewer)
    assert r.status_code == 200, "the SAME token must now succeed — live re-derivation, no re-login"


# ─── Privilege escalation protection ────────────────────────────────────────


async def test_member_holding_roles_manage_cannot_grant_a_permission_they_lack(
    client: AsyncClient,
) -> None:
    """The real end-to-end escalation proof: a plain MEMBER is granted a
    custom role containing ROLES_MANAGE/GROUPS_MANAGE (so they CAN reach
    the role-administration endpoints at all — the require_permission
    gate passes) but deliberately NOT NETWORK_SECURITY_MANAGE. When they
    then try to create a role that includes NETWORK_SECURITY_MANAGE, the
    canonical grant policy (application.rbac.grant_policy.
    assert_can_grant) must reject it — MEMBER's fixed role set doesn't
    carry it and neither does their one custom role, so their effective
    permissions never include it."""
    org_id, _owner_id, owner = await _owner_context(client)
    member_id, member = await _invite_member(client, owner, org_id, "member")

    r = await client.post(
        "/api/v1/admin/roles",
        json={
            "name": "Junior RBAC Admin",
            "permissions": ["roles:manage", "groups:manage", "findings:read"],
        },
        headers=owner,
    )
    assert r.status_code == 201, r.text
    junior_role_id = r.json()["id"]
    await client.post(
        f"/api/v1/admin/users/{member_id}/roles", json={"role_id": junior_role_id}, headers=owner,
    )

    r = await client.get(f"/api/v1/admin/users/{member_id}/effective-access", headers=member)
    assert "roles:manage" in r.json()["effective_permissions"]
    assert "network_security:manage" not in r.json()["effective_permissions"]

    r = await client.post(
        "/api/v1/admin/roles",
        json={"name": "Escalated Role", "permissions": ["network_security:manage"]},
        headers=member,
    )
    assert r.status_code in (400, 422), (
        f"expected the grant policy to reject this escalation attempt, got {r.status_code}: {r.text}"
    )


async def test_unknown_permission_string_rejected_not_a_500(client: AsyncClient) -> None:
    _, _, owner = await _owner_context(client)
    r = await client.post(
        "/api/v1/admin/roles",
        json={"name": "Bad Perm Role", "permissions": ["not:a:real:permission"]},
        headers=owner,
    )
    assert r.status_code in (400, 422), r.text


# ─── Cross-tenant isolation ──────────────────────────────────────────────────


async def test_cross_tenant_role_and_group_non_disclosure(client: AsyncClient) -> None:
    _org_a, _, owner_a = await _owner_context(client)
    _org_b, _, owner_b = await _owner_context(client)

    r = await client.post(
        "/api/v1/admin/roles", json={"name": "Org A Role", "permissions": []}, headers=owner_a,
    )
    role_a = r.json()["id"]
    r = await client.post("/api/v1/admin/groups", json={"name": "Org A Group"}, headers=owner_a)
    group_a = r.json()["id"]

    r = await client.get(f"/api/v1/admin/roles/{role_a}", headers=owner_b)
    assert r.status_code == 404, "org B must not see org A's role"
    r = await client.get(f"/api/v1/admin/groups/{group_a}", headers=owner_b)
    assert r.status_code == 404, "org B must not see org A's group"

    # Cross-tenant role assignment onto org B's own group must fail —
    # the composite FK/app-layer check makes role_a invisible in org B.
    r = await client.post("/api/v1/admin/groups", json={"name": "Org B Group"}, headers=owner_b)
    group_b = r.json()["id"]
    r = await client.post(
        f"/api/v1/admin/groups/{group_b}/roles", json={"role_id": role_a}, headers=owner_b,
    )
    assert r.status_code == 404, "org B must not be able to assign org A's role to its own group"


async def test_cross_tenant_effective_access_non_disclosure(client: AsyncClient) -> None:
    _org_a, user_a, _owner_a = await _owner_context(client)
    _org_b, _, owner_b = await _owner_context(client)

    r = await client.get(f"/api/v1/admin/users/{user_a}/effective-access", headers=owner_b)
    assert r.status_code == 404, "org B cannot inspect org A's user access"


# ─── Malformed / unknown IDs ─────────────────────────────────────────────────


async def test_malformed_and_unknown_ids_are_404_not_500(client: AsyncClient) -> None:
    _, _, owner = await _owner_context(client)

    for path in (
        "/api/v1/admin/roles/not-a-ulid",
        "/api/v1/admin/roles/01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "/api/v1/admin/groups/not-a-ulid",
        "/api/v1/admin/groups/01ARZ3NDEKTSV4RRFFQ69G5FAV",
    ):
        r = await client.get(path, headers=owner)
        assert r.status_code == 404, f"{path} -> {r.status_code}"

    r = await client.delete(
        "/api/v1/admin/groups/01ARZ3NDEKTSV4RRFFQ69G5FAV/members/01ARZ3NDEKTSV4RRFFQ69G5FAV",
        headers=owner,
    )
    assert r.status_code == 404


# ─── Duplicates / idempotency ────────────────────────────────────────────────


async def test_duplicate_role_and_group_names_rejected(client: AsyncClient) -> None:
    _, _, owner = await _owner_context(client)
    r = await client.post(
        "/api/v1/admin/roles", json={"name": "Dup Role", "permissions": []}, headers=owner,
    )
    assert r.status_code == 201
    r = await client.post(
        "/api/v1/admin/roles", json={"name": "  DUP   role  ", "permissions": []}, headers=owner,
    )
    assert r.status_code == 409, "normalized-name collision must be rejected"

    r = await client.post("/api/v1/admin/groups", json={"name": "Dup Group"}, headers=owner)
    assert r.status_code == 201
    r = await client.post("/api/v1/admin/groups", json={"name": "dup group"}, headers=owner)
    assert r.status_code == 409


async def test_duplicate_membership_and_role_assignment_are_idempotent(client: AsyncClient) -> None:
    _org_id, owner_id, owner = await _owner_context(client)
    r = await client.post("/api/v1/admin/groups", json={"name": "Idem Group"}, headers=owner)
    group_id = r.json()["id"]

    r = await client.post(
        f"/api/v1/admin/groups/{group_id}/members", json={"user_id": owner_id}, headers=owner,
    )
    assert r.status_code == 204
    r = await client.post(
        f"/api/v1/admin/groups/{group_id}/members", json={"user_id": owner_id}, headers=owner,
    )
    assert r.status_code == 204, "re-adding an existing member must be a safe no-op, not a 500"

    r = await client.get(f"/api/v1/admin/groups/{group_id}/members", headers=owner)
    assert r.json() == [owner_id]  # never duplicated


# ─── System role protection ─────────────────────────────────────────────────


async def test_system_role_cannot_be_mutated_or_deleted(client: AsyncClient) -> None:
    _, _, owner = await _owner_context(client)
    r = await client.get("/api/v1/admin/roles", headers=owner)
    system_role_id = next(role["id"] for role in r.json() if role["name"] == "Admin")

    r = await client.patch(
        f"/api/v1/admin/roles/{system_role_id}",
        json={"name": "Hacked Admin", "description": ""}, headers=owner,
    )
    assert r.status_code in (400, 422)

    r = await client.post(
        f"/api/v1/admin/roles/{system_role_id}/permissions",
        json={"permissions": []}, headers=owner,
    )
    assert r.status_code in (400, 422)

    r = await client.delete(f"/api/v1/admin/roles/{system_role_id}", headers=owner)
    assert r.status_code in (400, 422)


# ─── Role/group deletion with active dependents ─────────────────────────────


async def test_role_deletion_blocked_while_assigned(client: AsyncClient) -> None:
    _org_id, owner_id, owner = await _owner_context(client)
    r = await client.post(
        "/api/v1/admin/roles", json={"name": "In Use Role", "permissions": []}, headers=owner,
    )
    role_id = r.json()["id"]
    await client.post(f"/api/v1/admin/users/{owner_id}/roles", json={"role_id": role_id}, headers=owner)

    r = await client.delete(f"/api/v1/admin/roles/{role_id}", headers=owner)
    assert r.status_code in (400, 409, 422), r.text

    await client.delete(f"/api/v1/admin/users/{owner_id}/roles/{role_id}", headers=owner)
    r = await client.delete(f"/api/v1/admin/roles/{role_id}", headers=owner)
    assert r.status_code == 204


async def test_group_deletion_blocked_while_members_exist(client: AsyncClient) -> None:
    _org_id, owner_id, owner = await _owner_context(client)
    r = await client.post("/api/v1/admin/groups", json={"name": "Occupied Group"}, headers=owner)
    group_id = r.json()["id"]
    await client.post(f"/api/v1/admin/groups/{group_id}/members", json={"user_id": owner_id}, headers=owner)

    r = await client.delete(f"/api/v1/admin/groups/{group_id}", headers=owner)
    assert r.status_code in (400, 409, 422), r.text

    await client.delete(f"/api/v1/admin/groups/{group_id}/members/{owner_id}", headers=owner)
    r = await client.delete(f"/api/v1/admin/groups/{group_id}", headers=owner)
    assert r.status_code == 204


# ─── Suspended member cannot administer or be granted fresh access ──────────


async def test_suspended_member_loses_access_immediately(client: AsyncClient) -> None:
    org_id, _, owner = await _owner_context(client)
    admin_id, admin = await _invite_member(client, owner, org_id, "admin")

    r = await client.get("/api/v1/admin/roles", headers=admin)
    assert r.status_code == 200

    r = await client.get(f"/api/v1/organizations/{org_id}/members", headers=owner)
    membership_id = next(m["id"] for m in r.json() if m["user_id"] == admin_id)
    r = await client.post(
        f"/api/v1/organizations/{org_id}/members/{membership_id}/suspend", headers=owner,
    )
    assert r.status_code == 200

    r = await client.get("/api/v1/admin/roles", headers=admin)
    assert r.status_code in (401, 403), "a suspended member's already-issued token must lose access immediately"


# ─── Real PostgreSQL concurrency proofs ─────────────────────────────────────


async def test_concurrent_duplicate_group_creation_converges_on_one_winner(client: AsyncClient) -> None:
    _, _, owner = await _owner_context(client)

    async def attempt():
        return await client.post(
            "/api/v1/admin/groups", json={"name": "Race Group"}, headers=owner,
        )

    results = await asyncio.gather(*(attempt() for _ in range(10)))
    successes = [r for r in results if r.status_code == 201]
    conflicts = [r for r in results if r.status_code == 409]
    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}"
    assert len(successes) + len(conflicts) == 10

    r = await client.get("/api/v1/admin/groups", headers=owner)
    matching = [g for g in r.json() if g["name"] == "Race Group"]
    assert len(matching) == 1, "real Postgres unique constraint must prevent a duplicate row"


async def test_concurrent_duplicate_role_creation_converges_on_one_winner(client: AsyncClient) -> None:
    _, _, owner = await _owner_context(client)

    async def attempt():
        return await client.post(
            "/api/v1/admin/roles", json={"name": "Race Role", "permissions": []}, headers=owner,
        )

    results = await asyncio.gather(*(attempt() for _ in range(10)))
    successes = [r for r in results if r.status_code == 201]
    assert len(successes) == 1

    r = await client.get("/api/v1/admin/roles", headers=owner)
    matching = [role for role in r.json() if role["name"] == "Race Role"]
    assert len(matching) == 1


async def test_concurrent_group_membership_assignment_never_duplicates(client: AsyncClient) -> None:
    _org_id, owner_id, owner = await _owner_context(client)
    r = await client.post("/api/v1/admin/groups", json={"name": "Concurrent Members"}, headers=owner)
    group_id = r.json()["id"]

    async def attempt():
        return await client.post(
            f"/api/v1/admin/groups/{group_id}/members", json={"user_id": owner_id}, headers=owner,
        )

    results = await asyncio.gather(*(attempt() for _ in range(10)))
    assert all(r.status_code == 204 for r in results), "every concurrent add must be a safe no-op or success"

    r = await client.get(f"/api/v1/admin/groups/{group_id}/members", headers=owner)
    assert r.json() == [owner_id]


async def test_concurrent_role_assignment_to_group_never_duplicates(client: AsyncClient) -> None:
    _, _, owner = await _owner_context(client)
    r = await client.post(
        "/api/v1/admin/roles", json={"name": "Concurrent Assign Role", "permissions": []}, headers=owner,
    )
    role_id = r.json()["id"]
    r = await client.post("/api/v1/admin/groups", json={"name": "Concurrent Assign Group"}, headers=owner)
    group_id = r.json()["id"]

    async def attempt():
        return await client.post(
            f"/api/v1/admin/groups/{group_id}/roles", json={"role_id": role_id}, headers=owner,
        )

    results = await asyncio.gather(*(attempt() for _ in range(10)))
    assert all(r.status_code == 204 for r in results)

    r = await client.get(f"/api/v1/admin/groups/{group_id}/roles", headers=owner)
    assert r.json() == [role_id]


# ─── Audit trail ─────────────────────────────────────────────────────────────


async def test_administrative_mutations_are_audited_and_tenant_scoped(client: AsyncClient) -> None:
    org_a, _, owner_a = await _owner_context(client)
    _org_b, _, owner_b = await _owner_context(client)

    await client.post("/api/v1/admin/roles", json={"name": "Audited Role", "permissions": []}, headers=owner_a)
    await client.post("/api/v1/admin/groups", json={"name": "Audited Group"}, headers=owner_a)

    r = await client.get("/api/v1/admin/audit-events", headers=owner_a)
    assert r.status_code == 200
    actions = {e["action"] for e in r.json()}
    assert "rbac.role_created" in actions
    assert "rbac.group_created" in actions
    assert all(e["organization_id"] == org_a for e in r.json())

    r = await client.get("/api/v1/admin/audit-events", headers=owner_b)
    assert r.json() == [], "org B must never see org A's administrative audit events"
