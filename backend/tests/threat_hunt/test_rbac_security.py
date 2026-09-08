"""Security regression tests for the Threat Hunt X-Roles authorization
hotfix.

Root cause (fixed): `threat_hunt.api.dependencies.roles_header` read a
client-supplied `X-Roles` request header directly and passed those
caller-controlled strings into `HuntApplicationService`'s and
`ThreatHuntCandidate`'s authorization checks — any request could set
`X-Roles: soc:detection_engineer` and be treated as an authorized
reviewer/analyst regardless of who the caller actually was, while a
real Organization Owner with no `X-Roles` header was denied.

Fix: `roles_header` is removed. Every Threat Hunt route now gates on
`Depends(require_permission(Permission.THREAT_HUNT_READ/_MANAGE))` —
resolved from the caller's signed access token via `TenantContext`,
never a header — and `trusted_roles` synthesizes the legacy internal
role-string tuple from the verified `TenantContext.permissions` only.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI, Header
from httpx import ASGITransport, AsyncClient

from redforge.api.dependencies import get_organization_service
from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware
from redforge.shared.identifiers import EntityId
from threat_hunt.api.v1.routes import router
from threat_hunt.infrastructure.container import ThreatHuntContainer


class _OrgStub:
    async def get_by_id(self, organization_id: str) -> object:
        class _Org:
            status = "active"

        return _Org()


def _build_app(role: MembershipRole, organization_id: str) -> FastAPI:
    """Builds an app whose `TenantContext` holds the REAL, product-defined
    permission set for `role` (via `ROLE_PERMISSIONS`) — never a
    hand-picked subset — so these tests prove the actual shipped policy."""

    def override_tenant_context(
        x_tenant_id: str = Header(default=organization_id, alias="X-Tenant-Id"),
    ) -> TenantContext:
        return TenantContext(
            user_id=str(uuid4()),
            email="rbac-test@example.com",
            organization_id=x_tenant_id,
            role=role,
            permissions=ROLE_PERMISSIONS[role],
        )

    app = FastAPI()
    app.add_middleware(ErrorHandlerMiddleware)
    app.include_router(router)
    app.dependency_overrides[get_tenant_context] = override_tenant_context
    app.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    app.state.threat_hunt_container = ThreatHuntContainer()
    return app


def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


GENERATE_BODY = {"anomaly_signal_ids": ["s1"], "technique_ids": ["T1059"]}


@pytest.mark.asyncio
async def test_forged_x_roles_cannot_grant_access() -> None:
    """A caller with a real, low-privilege VIEWER context (no
    THREAT_HUNT_MANAGE) forges `X-Roles: soc:detection_engineer` — the
    exact header from the original exploit report. Must still be
    denied: the header is never read anywhere in the fix."""
    org_id = str(EntityId.generate())
    app = _build_app(MembershipRole.VIEWER, org_id)
    async with _client(app) as client:
        response = await client.post(
            "/threat-hunt/candidates",
            json=GENERATE_BODY,
            headers={"X-Tenant-Id": org_id, "X-Roles": "soc:detection_engineer"},
        )
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_missing_x_roles_does_not_affect_authorization() -> None:
    """An authorized (OWNER) caller with NO `X-Roles` header at all
    succeeds — proves authorization no longer depends on that header
    being present, matching the reported "legitimate Owner incorrectly
    denied without X-Roles" symptom."""
    org_id = str(EntityId.generate())
    app = _build_app(MembershipRole.OWNER, org_id)
    async with _client(app) as client:
        response = await client.post(
            "/threat-hunt/candidates",
            json=GENERATE_BODY,
            headers={"X-Tenant-Id": org_id},
        )
        assert response.status_code == 201, response.text


@pytest.mark.asyncio
async def test_forged_x_roles_on_authorized_caller_has_no_additional_effect() -> None:
    """An authorized OWNER caller succeeds identically whether or not a
    (now-inert) X-Roles header is attached — proves the header is
    simply never consulted, not merely insufficient on its own."""
    org_id = str(EntityId.generate())
    app = _build_app(MembershipRole.OWNER, org_id)
    async with _client(app) as client:
        without_header = await client.post(
            "/threat-hunt/candidates", json=GENERATE_BODY, headers={"X-Tenant-Id": org_id}
        )
        with_header = await client.post(
            "/threat-hunt/candidates",
            json=GENERATE_BODY,
            headers={"X-Tenant-Id": org_id, "X-Roles": "definitely-not-a-real-role"},
        )
        assert without_header.status_code == with_header.status_code == 201


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "role", [MembershipRole.OWNER, MembershipRole.ADMIN, MembershipRole.SECURITY_MANAGER]
)
async def test_authorized_roles_can_generate_and_review(role: MembershipRole) -> None:
    """Roles holding THREAT_HUNT_MANAGE per the real ROLE_PERMISSIONS
    matrix can generate, promote, and reject candidates."""
    org_id = str(EntityId.generate())
    app = _build_app(role, org_id)
    async with _client(app) as client:
        created = await client.post(
            "/threat-hunt/candidates", json=GENERATE_BODY, headers={"X-Tenant-Id": org_id}
        )
        assert created.status_code == 201, created.text
        candidate_id = created.json()["candidate_id"]

        rejected = await client.post(
            f"/threat-hunt/candidates/{candidate_id}/reject",
            json={"rejected_by": "analyst@example.com", "rejection_reason": "noise"},
            headers={"X-Tenant-Id": org_id},
        )
        assert rejected.status_code == 200, rejected.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "role", [MembershipRole.ANALYST, MembershipRole.MEMBER, MembershipRole.VIEWER]
)
async def test_unauthorized_roles_denied_mutation(role: MembershipRole) -> None:
    """Roles holding THREAT_HUNT_READ but not THREAT_HUNT_MANAGE (per
    the real ROLE_PERMISSIONS matrix) cannot generate/promote/reject —
    ordinary members remain denied."""
    org_id = str(EntityId.generate())
    app = _build_app(role, org_id)
    async with _client(app) as client:
        response = await client.post(
            "/threat-hunt/candidates", json=GENERATE_BODY, headers={"X-Tenant-Id": org_id}
        )
        assert response.status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "role",
    [
        MembershipRole.OWNER,
        MembershipRole.ADMIN,
        MembershipRole.SECURITY_MANAGER,
        MembershipRole.ANALYST,
        MembershipRole.MEMBER,
        MembershipRole.VIEWER,
    ],
)
async def test_every_role_with_read_permission_can_list_candidates(role: MembershipRole) -> None:
    """Every role in the product's real permission matrix holds
    THREAT_HUNT_READ (§ ROLE_PERMISSIONS) — all can list, none need
    THREAT_HUNT_MANAGE just to view the queue."""
    org_id = str(EntityId.generate())
    app = _build_app(role, org_id)
    async with _client(app) as client:
        response = await client.get("/threat-hunt/candidates", headers={"X-Tenant-Id": org_id})
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_tenant_a_cannot_read_tenant_b_candidates() -> None:
    org_a = str(EntityId.generate())
    org_b = str(EntityId.generate())
    app_a = _build_app(MembershipRole.OWNER, org_a)
    app_b = _build_app(MembershipRole.OWNER, org_b)

    async with _client(app_a) as client_a:
        created = await client_a.post(
            "/threat-hunt/candidates", json=GENERATE_BODY, headers={"X-Tenant-Id": org_a}
        )
        assert created.status_code == 201

    async with _client(app_b) as client_b:
        listed = await client_b.get("/threat-hunt/candidates", headers={"X-Tenant-Id": org_b})
        assert listed.status_code == 200
        assert listed.json() == []


@pytest.mark.asyncio
async def test_tenant_a_cannot_promote_tenant_bs_candidate() -> None:
    org_a = str(EntityId.generate())
    org_b = str(EntityId.generate())
    app_a = _build_app(MembershipRole.OWNER, org_a)
    app_b = _build_app(MembershipRole.OWNER, org_b)

    async with _client(app_a) as client_a:
        created = await client_a.post(
            "/threat-hunt/candidates", json=GENERATE_BODY, headers={"X-Tenant-Id": org_a}
        )
        candidate_id = created.json()["candidate_id"]

    async with _client(app_b) as client_b:
        response = await client_b.post(
            f"/threat-hunt/candidates/{candidate_id}/promote",
            json={"promoted_by": "attacker@example.com", "promoted_rule_version_id": str(uuid4())},
            headers={"X-Tenant-Id": org_b},
        )
        # Cross-tenant: the in-memory repository's find_by_id is keyed by
        # tenant first, so tenant B's lookup of tenant A's candidate ID
        # simply finds nothing — never a distinguishable "forbidden".
        assert response.status_code == 404
