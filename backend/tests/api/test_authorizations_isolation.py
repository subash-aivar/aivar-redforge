"""Adversarial tests for the M10 Security Authorization & Execution
Policy control plane.

Exercises the full HTTP path (route -> security dependency -> service
-> repository -> response), matching test_directory_security_isolation.py's
pattern: real router + real services + an in-memory SQLite engine
(schema created from ORM metadata), with dependency_overrides only for
infrastructure singletons.

Covers M10 adversarial checklist items 1-29 and 32 (see
docs/M10_AUTHORIZED_PT_SCOPE_EXECUTION_POLICY_REPORT.md for the full
mapping). Concurrency items 30-31 require real PostgreSQL and live in
tests/integration/test_authorization_race.py.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_auth_service,
    get_effective_access_service,
    get_execution_policy_service,
    get_organization_service,
    get_security_authorization_service,
    get_token_service,
    get_user_status_service,
)
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.authorizations import router as authorizations_router
from redforge.api.v1.organizations import router as organizations_router
from redforge.application.auth import AuthService
from redforge.application.authorization import (
    ExecutionPolicyService,
    SecurityAuthorizationService,
)
from redforge.application.organizations import OrganizationService
from redforge.domain.identity.value_objects import MembershipRole
from redforge.infrastructure.audit.logger import InMemoryAuditLog
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (  # noqa: F401
    MembershipModel,
    OrganizationModel,
    SecurityAuthorizationApprovalModel,
    SecurityAuthorizationDecisionModel,
    SecurityAuthorizationModel,
    SecurityAuthorizationScopeModel,
    UserModel,
)
from redforge.infrastructure.database.repositories.membership_repository import (
    SqlAlchemyMembershipRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio


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


class _FakeOwnershipChecker:
    """Test double for EntityOwnershipPort: an entity is "owned" only if
    explicitly registered for (organization_id, entity_type, entity_id).
    Exercises the REAL SecurityAuthorizationService/ExecutionPolicyService
    scope-verification code path without standing up the full AITarget/
    AIAsset infrastructure — the port is exactly what those services
    depend on, so this is a legitimate boundary to fake."""

    def __init__(self) -> None:
        self._owned: set[tuple[str, str, str]] = set()

    def register(self, organization_id: str, entity_type: str, entity_id: str) -> None:
        self._owned.add((organization_id, entity_type, entity_id))

    async def is_owned_by_organization(
        self, entity_type: str, entity_id: str, organization_id: str
    ) -> bool:
        return (organization_id, entity_type, entity_id) in self._owned


@pytest.fixture
def audit() -> InMemoryAuditLog:
    return InMemoryAuditLog()


@pytest.fixture
def ownership() -> _FakeOwnershipChecker:
    return _FakeOwnershipChecker()


@pytest.fixture
async def app(audit: InMemoryAuditLog, ownership: _FakeOwnershipChecker):
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[t for t in Base.metadata.sorted_tables if t.schema is None],
        )

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    events = InMemoryEventPublisher()
    hasher = Argon2PasswordHasher(time_cost=1, memory_cost=16384, parallelism=1)
    tokens = JWTTokenService(
        secret_key="test-secret-key-that-is-long-enough-32!", access_ttl=3600,
    )
    org_service = OrganizationService(factory, events, audit)
    auth_service = AuthService(factory, hasher, tokens, events)
    authorization_service = SecurityAuthorizationService(
        factory, events, audit, ownership_checker=ownership,
    )
    policy_service = ExecutionPolicyService(factory, ownership_checker=ownership)

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(organizations_router, prefix="/api/v1")
    test_app.include_router(authorizations_router, prefix="/api/v1")

    test_app.dependency_overrides[get_organization_service] = lambda: org_service
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_effective_access_service] = lambda: _NoOpEffectiveAccessService()
    test_app.dependency_overrides[get_auth_service] = lambda: auth_service
    test_app.dependency_overrides[get_token_service] = lambda: tokens
    test_app.dependency_overrides[get_security_authorization_service] = lambda: authorization_service
    test_app.dependency_overrides[get_execution_policy_service] = lambda: policy_service

    yield test_app, factory
    await engine.dispose()


@pytest.fixture
async def client(app):
    test_app, _factory = app
    transport = ASGITransport(app=test_app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _register(client: AsyncClient, email: str) -> tuple[str, str]:
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
    """Register + create an organization (auto OWNER) + select it.
    Returns (scoped_owner_token, organization_id, owner_user_id)."""
    user_id, unscoped = await _register(client, email)
    create_resp = await client.post(
        "/api/v1/organizations", json={"name": name, "slug": slug},
        headers=_auth_headers(unscoped),
    )
    assert create_resp.status_code == 201, create_resp.text
    org_id: str = create_resp.json()["id"]
    scoped = await _select(client, unscoped, org_id)
    return scoped, org_id, user_id


async def _add_member(
    app_factory, client: AsyncClient, org_id: str, email: str, role: MembershipRole,
) -> str:
    """Add a second member to an existing org directly via the
    membership repository (bypassing the invite/accept email flow,
    which is orthogonal to M10) and return their scoped token."""
    user_id, unscoped = await _register(client, email)
    async with SessionUnitOfWork(app_factory) as uow:
        from redforge.domain.identity.entities import Membership

        repo = SqlAlchemyMembershipRepository(uow.session)
        membership = Membership.create(
            user_id=EntityId.from_string(user_id),
            organization_id=EntityId.from_string(org_id),
            role=role,
        )
        await repo.save(membership)
        await uow.commit()
    return await _select(client, unscoped, org_id)


def _window(hours_from_now: int = 0, duration_hours: int = 24) -> tuple[str, str]:
    start = datetime.now(UTC) + timedelta(hours=hours_from_now)
    end = start + timedelta(hours=duration_hours)
    return start.isoformat(), end.isoformat()


async def _create_authorization(
    client: AsyncClient,
    token: str,
    *,
    action_classes: list[str] | None = None,
    entity_id: str = "target-1",
    entity_type: str = "ai_target",
    valid_from: str | None = None,
    valid_until: str | None = None,
    extra: dict | None = None,
) -> dict:
    vf, vu = _window()
    body = {
        "action_classes": action_classes or ["safe_validation"],
        "scope": [{"entity_type": entity_type, "entity_id": entity_id}],
        "valid_from": valid_from or vf,
        "valid_until": valid_until or vu,
    }
    if extra:
        body.update(extra)
    resp = await client.post(
        "/api/v1/authorizations", json=body, headers=_auth_headers(token),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _full_lifecycle_to_active(
    app_factory, client: AsyncClient, requester_token: str, org_id: str,
    ownership: _FakeOwnershipChecker, *,
    action_classes: list[str] | None = None,
    entity_id: str = "target-active",
    valid_from: str | None = None,
    valid_until: str | None = None,
    approver_role: MembershipRole = MembershipRole.ADMIN,
) -> tuple[dict, str]:
    """Create, register scope entity as owned, submit, and approve (by
    a distinct ADMIN approver). Returns (authorization_json, approver_token)."""
    ownership.register(org_id, "ai_target", entity_id)
    authorization = await _create_authorization(
        client, requester_token, action_classes=action_classes, entity_id=entity_id,
        valid_from=valid_from, valid_until=valid_until,
    )
    auth_id = authorization["id"]
    submit_resp = await client.post(
        f"/api/v1/authorizations/{auth_id}/submit", headers=_auth_headers(requester_token),
    )
    assert submit_resp.status_code == 200, submit_resp.text

    approver_token = await _add_member(
        app_factory, client, org_id, f"approver-{auth_id}@test.com", approver_role,
    )
    approve_resp = await client.post(
        f"/api/v1/authorizations/{auth_id}/approve", headers=_auth_headers(approver_token),
    )
    assert approve_resp.status_code == 200, approve_resp.text
    return approve_resp.json(), approver_token


async def _evaluate(
    client: AsyncClient, token: str, action_class: str, entity_id: str = "target-1",
    entity_type: str = "ai_target",
) -> dict:
    resp = await client.post(
        "/api/v1/authorizations/evaluate",
        json={
            "action_class": action_class,
            "entities": [{"entity_type": entity_type, "entity_id": entity_id}],
        },
        headers=_auth_headers(token),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


# ─── 1-2: Tenant isolation & non-disclosure ───────────────────────────────────


class TestTenantIsolation:
    async def test_tenant_a_authorization_invisible_to_tenant_b(
        self, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        a_token, a_org, _ = await _create_org_and_select(client, "a1@test.com", "OrgA", "org-a1")
        b_token, _b_org, _ = await _create_org_and_select(client, "b1@test.com", "OrgB", "org-b1")

        ownership.register(a_org, "ai_target", "target-1")
        authorization = await _create_authorization(client, a_token)
        auth_id = authorization["id"]

        b_get = await client.get(
            f"/api/v1/authorizations/{auth_id}", headers=_auth_headers(b_token),
        )
        assert b_get.status_code == 404

        b_list = await client.get("/api/v1/authorizations", headers=_auth_headers(b_token))
        assert b_list.json() == []

    async def test_guessed_foreign_authorization_id_non_disclosing(
        self, client: AsyncClient,
    ) -> None:
        token, _org, _ = await _create_org_and_select(client, "a2@test.com", "OrgA", "org-a2")
        guessed_id = str(EntityId.generate())
        resp = await client.get(
            f"/api/v1/authorizations/{guessed_id}", headers=_auth_headers(token),
        )
        assert resp.status_code == 404


# ─── 3-4: Scope must be canonical, tenant-owned ───────────────────────────────


class TestScopeCanonicalOwnership:
    async def test_foreign_target_cannot_enter_scope(
        self, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        token, _org_id, _ = await _create_org_and_select(client, "a3@test.com", "OrgA", "org-a3")
        # Deliberately NOT registered as owned by any org.
        resp = await client.post(
            "/api/v1/authorizations",
            json={
                "action_classes": ["safe_validation"],
                "scope": [{"entity_type": "ai_target", "entity_id": "not-owned-target"}],
                "valid_from": _window()[0], "valid_until": _window()[1],
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code >= 400

    async def test_foreign_asset_cannot_enter_scope(
        self, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        token, _org_id, _ = await _create_org_and_select(client, "a4@test.com", "OrgA", "org-a4")
        resp = await client.post(
            "/api/v1/authorizations",
            json={
                "action_classes": ["safe_validation"],
                "scope": [{"entity_type": "ai_asset", "entity_id": "not-owned-asset"}],
                "valid_from": _window()[0], "valid_until": _window()[1],
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code >= 400


# ─── 5-8: Client cannot forge server-decided fields ───────────────────────────


class TestClientCannotForge:
    async def test_client_cannot_create_active_authorization(
        self, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        token, org_id, _ = await _create_org_and_select(client, "a5@test.com", "OrgA", "org-a5")
        ownership.register(org_id, "ai_target", "target-1")
        authorization = await _create_authorization(
            client, token, extra={"status": "active"},
        )
        assert authorization["status"] == "draft"

    async def test_client_cannot_forge_approver(
        self, app, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        _test_app, factory = app
        token, org_id, _requester_id = await _create_org_and_select(
            client, "a6@test.com", "OrgA", "org-a6",
        )
        ownership.register(org_id, "ai_target", "target-6")
        authorization = await _create_authorization(client, token, entity_id="target-6")
        auth_id = authorization["id"]
        await client.post(
            f"/api/v1/authorizations/{auth_id}/submit", headers=_auth_headers(token),
        )
        approver_token = await _add_member(
            factory, client, org_id, "approver6@test.com", MembershipRole.ADMIN,
        )
        # Attempt to forge a different approver identity in the body —
        # the endpoint has no such field; approver is always the caller.
        resp = await client.post(
            f"/api/v1/authorizations/{auth_id}/approve",
            json={"approver_user_id": "someone-else"},
            headers=_auth_headers(approver_token),
        )
        assert resp.status_code == 200
        get_resp = await client.get(
            f"/api/v1/authorizations/{auth_id}", headers=_auth_headers(token),
        )
        assert get_resp.json()["approval"]["approver_user_id"] != "someone-else"

    async def test_client_cannot_forge_policy_decision(
        self, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        token, org_id, _ = await _create_org_and_select(client, "a7@test.com", "OrgA", "org-a7")
        ownership.register(org_id, "ai_target", "ghost")
        result = await _evaluate(client, token, "safe_validation", entity_id="ghost")
        # No authorization exists — server must DENY regardless of any
        # client-side claim; the request body has no "decision" field.
        assert result["decision"] == "deny"

    async def test_client_cannot_forge_reason_code(
        self, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        token, org_id, _ = await _create_org_and_select(client, "a8@test.com", "OrgA", "org-a8")
        ownership.register(org_id, "ai_target", "ghost")
        result = await _evaluate(client, token, "safe_validation", entity_id="ghost")
        assert result["reason_code"] == "AUTHORIZATION_NOT_FOUND"


# ─── 9-10: Approval RBAC ──────────────────────────────────────────────────────


class TestApprovalRBAC:
    async def test_requester_cannot_self_approve(
        self, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        token, org_id, _ = await _create_org_and_select(client, "a9@test.com", "OrgA", "org-a9")
        ownership.register(org_id, "ai_target", "target-9")
        authorization = await _create_authorization(client, token, entity_id="target-9")
        auth_id = authorization["id"]
        await client.post(
            f"/api/v1/authorizations/{auth_id}/submit", headers=_auth_headers(token),
        )
        resp = await client.post(
            f"/api/v1/authorizations/{auth_id}/approve", headers=_auth_headers(token),
        )
        assert resp.status_code >= 400

    async def test_unauthorized_user_cannot_approve(
        self, app, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        _test_app, factory = app
        token, org_id, _ = await _create_org_and_select(client, "a10@test.com", "OrgA", "org-a10")
        ownership.register(org_id, "ai_target", "target-10")
        authorization = await _create_authorization(client, token, entity_id="target-10")
        auth_id = authorization["id"]
        await client.post(
            f"/api/v1/authorizations/{auth_id}/submit", headers=_auth_headers(token),
        )
        viewer_token = await _add_member(
            factory, client, org_id, "viewer10@test.com", MembershipRole.VIEWER,
        )
        resp = await client.post(
            f"/api/v1/authorizations/{auth_id}/approve", headers=_auth_headers(viewer_token),
        )
        assert resp.status_code == 403


# ─── 11: Approval history preserved ───────────────────────────────────────────


class TestApprovalHistory:
    async def test_approval_history_is_preserved(
        self, app, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        _test_app, factory = app
        token, org_id, _ = await _create_org_and_select(client, "a11@test.com", "OrgA", "org-a11")
        ownership.register(org_id, "ai_target", "target-11")
        authorization = await _create_authorization(client, token, entity_id="target-11")
        auth_id = authorization["id"]
        await client.post(
            f"/api/v1/authorizations/{auth_id}/submit", headers=_auth_headers(token),
        )
        approver_token = await _add_member(
            factory, client, org_id, "approver11@test.com", MembershipRole.ADMIN,
        )
        reject_resp = await client.post(
            f"/api/v1/authorizations/{auth_id}/reject",
            json={"reason": "not justified"},
            headers=_auth_headers(approver_token),
        )
        assert reject_resp.status_code == 200
        body = reject_resp.json()
        assert body["status"] == "rejected"
        assert body["approval"]["decision"] == "rejected"
        assert body["approval"]["decided_at"] is not None
        assert body["approval"]["reason"] == "not justified"
        assert body["approval"]["requester_user_id"]


# ─── 12-14: Terminal/expired authorizations cannot ALLOW ─────────────────────


class TestTerminalStatesCannotAllow:
    async def test_rejected_authorization_cannot_allow(
        self, app, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        _test_app, factory = app
        token, org_id, _ = await _create_org_and_select(client, "a12@test.com", "OrgA", "org-a12")
        ownership.register(org_id, "ai_target", "target-12")
        authorization = await _create_authorization(client, token, entity_id="target-12")
        auth_id = authorization["id"]
        await client.post(
            f"/api/v1/authorizations/{auth_id}/submit", headers=_auth_headers(token),
        )
        approver_token = await _add_member(
            factory, client, org_id, "approver12@test.com", MembershipRole.ADMIN,
        )
        await client.post(
            f"/api/v1/authorizations/{auth_id}/reject", headers=_auth_headers(approver_token),
        )
        result = await _evaluate(client, token, "safe_validation", entity_id="target-12")
        assert result["decision"] != "allow"

    async def test_revoked_authorization_cannot_allow(
        self, app, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        _test_app, factory = app
        token, org_id, _ = await _create_org_and_select(client, "a13@test.com", "OrgA", "org-a13")
        _authorization, _approver = await _full_lifecycle_to_active(
            factory, client, token, org_id, ownership, entity_id="target-13",
        )
        auth_id = _authorization["id"]
        await client.post(
            f"/api/v1/authorizations/{auth_id}/revoke", headers=_auth_headers(token),
        )
        result = await _evaluate(client, token, "safe_validation", entity_id="target-13")
        assert result["decision"] != "allow"

    async def test_expired_authorization_cannot_allow(
        self, app, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        _test_app, factory = app
        token, org_id, _ = await _create_org_and_select(client, "a14@test.com", "OrgA", "org-a14")
        past_start = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
        past_end = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        _authorization, _approver = await _full_lifecycle_to_active(
            factory, client, token, org_id, ownership, entity_id="target-14",
            valid_from=past_start, valid_until=past_end,
        )
        result = await _evaluate(client, token, "safe_validation", entity_id="target-14")
        assert result["decision"] != "allow"
        assert result["reason_code"] == "AUTHORIZATION_EXPIRED"


# ─── 15-17: Scope/action/unknown-class denial ─────────────────────────────────


class TestScopeAndActionDenial:
    async def test_out_of_scope_entity_deny(
        self, app, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        _test_app, factory = app
        token, org_id, _ = await _create_org_and_select(client, "a15@test.com", "OrgA", "org-a15")
        await _full_lifecycle_to_active(
            factory, client, token, org_id, ownership, entity_id="target-15-authorized",
        )
        # A second, legitimately tenant-owned target that simply isn't
        # in THIS authorization's scope — distinct from a foreign/
        # unowned entity (which would DENY with TENANT_MISMATCH instead).
        ownership.register(org_id, "ai_target", "target-15-different")
        result = await _evaluate(
            client, token, "safe_validation", entity_id="target-15-different",
        )
        assert result["decision"] != "allow"
        assert result["reason_code"] == "ENTITY_NOT_IN_SCOPE"

    async def test_out_of_scope_action_deny(
        self, app, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        _test_app, factory = app
        token, org_id, _ = await _create_org_and_select(client, "a16@test.com", "OrgA", "org-a16")
        await _full_lifecycle_to_active(
            factory, client, token, org_id, ownership, entity_id="target-16",
            action_classes=["safe_validation"],
        )
        result = await _evaluate(client, token, "active_validation", entity_id="target-16")
        assert result["decision"] != "allow"
        assert result["reason_code"] == "ACTION_NOT_IN_SCOPE"

    async def test_unknown_action_class_fails_safe(self, client: AsyncClient) -> None:
        token, _org, _ = await _create_org_and_select(client, "a17@test.com", "OrgA", "org-a17")
        result = await _evaluate(client, token, "totally_made_up_action")
        assert result["decision"] == "deny"
        assert result["reason_code"] == "ACTION_CLASS_DENIED"


# ─── 18-20: Approval workflow produces correct decisions ──────────────────────


class TestApprovalWorkflowDecisions:
    async def test_active_valid_in_scope_authorization_allow(
        self, app, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        _test_app, factory = app
        token, org_id, _ = await _create_org_and_select(client, "a18@test.com", "OrgA", "org-a18")
        await _full_lifecycle_to_active(
            factory, client, token, org_id, ownership, entity_id="target-18",
        )
        result = await _evaluate(client, token, "safe_validation", entity_id="target-18")
        assert result["decision"] == "allow"
        assert result["reason_code"] == "ALLOWED_BY_ACTIVE_AUTHORIZATION"
        assert result["decision_id"]

    async def test_action_requiring_approval_returns_approval_required_before_approval(
        self, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        token, org_id, _ = await _create_org_and_select(client, "a19@test.com", "OrgA", "org-a19")
        ownership.register(org_id, "ai_target", "target-19")
        authorization = await _create_authorization(client, token, entity_id="target-19")
        auth_id = authorization["id"]
        await client.post(
            f"/api/v1/authorizations/{auth_id}/submit", headers=_auth_headers(token),
        )
        result = await _evaluate(client, token, "safe_validation", entity_id="target-19")
        assert result["decision"] == "approval_required"
        assert result["reason_code"] == "APPROVAL_REQUIRED"

    async def test_approval_makes_eligible_request_allow(
        self, app, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        _test_app, factory = app
        token, org_id, _ = await _create_org_and_select(client, "a20@test.com", "OrgA", "org-a20")
        await _full_lifecycle_to_active(
            factory, client, token, org_id, ownership, entity_id="target-20",
        )
        result = await _evaluate(client, token, "safe_validation", entity_id="target-20")
        assert result["decision"] == "allow"


# ─── 21-22: Revocation/expiration change next decision ───────────────────────


class TestTimeOfUseChangesNextDecision:
    async def test_revocation_changes_next_decision_to_deny(
        self, app, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        _test_app, factory = app
        token, org_id, _ = await _create_org_and_select(client, "a21@test.com", "OrgA", "org-a21")
        authorization, _approver = await _full_lifecycle_to_active(
            factory, client, token, org_id, ownership, entity_id="target-21",
        )
        before = await _evaluate(client, token, "safe_validation", entity_id="target-21")
        assert before["decision"] == "allow"

        await client.post(
            f"/api/v1/authorizations/{authorization['id']}/revoke",
            headers=_auth_headers(token),
        )
        after = await _evaluate(client, token, "safe_validation", entity_id="target-21")
        assert after["decision"] != "allow"

    async def test_expiration_changes_next_decision_to_deny(
        self, app, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        _test_app, factory = app
        token, org_id, _ = await _create_org_and_select(client, "a22@test.com", "OrgA", "org-a22")
        near_future = (datetime.now(UTC) + timedelta(milliseconds=200)).isoformat()
        await _full_lifecycle_to_active(
            factory, client, token, org_id, ownership, entity_id="target-22",
            valid_from=datetime.now(UTC).isoformat(),
            valid_until=near_future,
        )
        before = await _evaluate(client, token, "safe_validation", entity_id="target-22")
        assert before["decision"] == "allow"

        import asyncio
        await asyncio.sleep(0.4)

        after = await _evaluate(client, token, "safe_validation", entity_id="target-22")
        assert after["decision"] != "allow"
        assert after["reason_code"] == "AUTHORIZATION_EXPIRED"


# ─── 23-24: Decisions are tenant-scoped and audited ───────────────────────────


class TestDecisionAudit:
    async def test_decision_is_tenant_scoped(self, client: AsyncClient) -> None:
        a_token, _a_org, _ = await _create_org_and_select(client, "a23@test.com", "OrgA", "org-a23")
        b_token, _b_org, _ = await _create_org_and_select(client, "b23@test.com", "OrgB", "org-b23")

        await _evaluate(client, a_token, "safe_validation", entity_id="shared-id")
        a_decisions = await client.get(
            "/api/v1/authorizations/decisions", headers=_auth_headers(a_token),
        )
        b_decisions = await client.get(
            "/api/v1/authorizations/decisions", headers=_auth_headers(b_token),
        )
        assert len(a_decisions.json()) >= 1
        assert b_decisions.json() == []

    async def test_decision_audit_row_is_created(self, client: AsyncClient) -> None:
        token, _org, _ = await _create_org_and_select(client, "a24@test.com", "OrgA", "org-a24")
        result = await _evaluate(client, token, "safe_validation", entity_id="target-24")
        history = await client.get(
            "/api/v1/authorizations/decisions", headers=_auth_headers(token),
        )
        ids = {row["id"] for row in history.json()}
        assert result["decision_id"] in ids


# ─── 25: No secrets in persistence/APIs ───────────────────────────────────────


class TestNoSecretsPersisted:
    async def test_no_raw_secrets_in_authorization_response(
        self, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        token, org_id, _ = await _create_org_and_select(client, "a25@test.com", "OrgA", "org-a25")
        ownership.register(org_id, "ai_target", "target-25")
        authorization = await _create_authorization(client, token, entity_id="target-25")
        serialized = str(authorization).lower()
        for forbidden in ("password", "secret", "private_key", "bearer "):
            assert forbidden not in serialized
        # Structural check: response has exactly the documented fields —
        # no credential/token/secret-shaped keys anywhere.
        assert set(authorization.keys()) == {
            "id", "organization_id", "requester_user_id", "status", "action_classes",
            "scope", "valid_from", "valid_until", "created_at", "updated_at", "approval",
        }


# ─── 26-27: Lifecycle/bypass cannot be circumvented from the browser ─────────


class TestLifecycleBypassPrevention:
    async def test_browser_cannot_bypass_lifecycle_directly_to_active(
        self, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        token, org_id, _ = await _create_org_and_select(client, "a26@test.com", "OrgA", "org-a26")
        ownership.register(org_id, "ai_target", "target-26")
        authorization = await _create_authorization(
            client, token, entity_id="target-26", extra={"status": "active"},
        )
        assert authorization["status"] == "draft"
        # Approving before submission is illegal (no PENDING_APPROVAL state yet).
        resp = await client.post(
            f"/api/v1/authorizations/{authorization['id']}/approve",
            headers=_auth_headers(token),
        )
        assert resp.status_code >= 400

    async def test_direct_execution_boundary_without_policy_decision_rejected(self) -> None:
        """Regression test living alongside the CampaignEngine gate
        itself: see
        tests/unit/test_campaign_engine.py::TestM10ExecutionPolicyGate::test_cannot_construct_without_execution_policy_service.
        Documented here so the M10 adversarial checklist is traceable
        from one file."""
        from redforge.application.campaigns.campaign_engine import CampaignEngine

        with pytest.raises(TypeError):
            CampaignEngine(  # type: ignore[call-arg]
                validation_service=object(),  # type: ignore[arg-type]
                target_selector=object(),  # type: ignore[arg-type]
                campaign_repository=object(),  # type: ignore[arg-type]
            )


# ─── 28-29: No offensive execution introduced; no hardcoded Super Admin ──────


class TestNoOffensiveExecutionOrHardcodedIdentity:
    async def test_no_active_exploit_endpoint_introduced(self, client: AsyncClient) -> None:
        token, _org, _ = await _create_org_and_select(client, "a28@test.com", "OrgA", "org-a28")
        for forbidden_path in (
            "/api/v1/authorizations/execute",
            "/api/v1/authorizations/exploit",
            "/api/v1/execution/run",
        ):
            resp = await client.post(forbidden_path, json={}, headers=_auth_headers(token))
            assert resp.status_code in (404, 405)

    async def test_exploit_execution_action_class_always_denied(
        self, client: AsyncClient,
    ) -> None:
        token, _org_id, _ = await _create_org_and_select(client, "a28b@test.com", "OrgA", "org-a28b")
        resp = await client.post(
            "/api/v1/authorizations",
            json={
                "action_classes": ["exploit_execution"],
                "scope": [{"entity_type": "ai_target", "entity_id": "target-28b"}],
                "valid_from": _window()[0], "valid_until": _window()[1],
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code >= 400

    async def test_no_hardcoded_super_admin_identity(
        self, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        """No email/name string is special-cased anywhere in the approval
        path. Even the organization's own OWNER — the highest-privilege
        identity in the tenant RBAC model — cannot approve their own
        authorization. If any hardcoded identity bypass existed, an
        OWNER account would be the most likely place for it; proving
        OWNER still hits SelfApprovalForbiddenError demonstrates the
        rule is identity-blind, driven purely by
        requester_user_id == approver_user_id."""
        token, org_id, _ = await _create_org_and_select(
            client, "totally-not-subash@test.com", "OrgA", "org-a28c",
        )
        ownership.register(org_id, "ai_target", "target-28c")
        authorization = await _create_authorization(client, token, entity_id="target-28c")
        auth_id = authorization["id"]
        await client.post(
            f"/api/v1/authorizations/{auth_id}/submit", headers=_auth_headers(token),
        )
        resp = await client.post(
            f"/api/v1/authorizations/{auth_id}/approve", headers=_auth_headers(token),
        )
        assert resp.status_code >= 400


# ─── 32: Invalid lifecycle transition rejected ────────────────────────────────


class TestInvalidLifecycleTransition:
    async def test_invalid_lifecycle_transition_rejected(
        self, app, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        _test_app, factory = app
        token, org_id, _ = await _create_org_and_select(client, "a32@test.com", "OrgA", "org-a32")
        authorization, _approver = await _full_lifecycle_to_active(
            factory, client, token, org_id, ownership, entity_id="target-32",
        )
        auth_id = authorization["id"]
        # ACTIVE -> submit again is illegal (only DRAFT -> PENDING_APPROVAL).
        resp = await client.post(
            f"/api/v1/authorizations/{auth_id}/submit", headers=_auth_headers(token),
        )
        assert resp.status_code >= 400

        # ACTIVE -> approve again is illegal (only PENDING_APPROVAL -> ACTIVE).
        approver_token = await _add_member(
            factory, client, org_id, "approver32b@test.com", MembershipRole.ADMIN,
        )
        resp2 = await client.post(
            f"/api/v1/authorizations/{auth_id}/approve", headers=_auth_headers(approver_token),
        )
        assert resp2.status_code >= 400


# ─── Overview summary is backend-derived, not fabricated ─────────────────────


class TestSummaryEndpoint:
    async def test_summary_reflects_real_counts_and_is_tenant_scoped(
        self, client: AsyncClient, ownership: _FakeOwnershipChecker,
    ) -> None:
        a_token, a_org, _ = await _create_org_and_select(client, "a33@test.com", "OrgA", "org-a33")
        b_token, _b_org, _ = await _create_org_and_select(client, "b33@test.com", "OrgB", "org-b33")

        ownership.register(a_org, "ai_target", "target-33a")
        ownership.register(a_org, "ai_target", "target-33b")
        await _create_authorization(client, a_token, entity_id="target-33a")
        await _create_authorization(client, a_token, entity_id="target-33b")

        a_summary = await client.get("/api/v1/authorizations/summary", headers=_auth_headers(a_token))
        assert a_summary.status_code == 200
        assert a_summary.json()["draft"] == 2
        assert a_summary.json()["active"] == 0

        b_summary = await client.get("/api/v1/authorizations/summary", headers=_auth_headers(b_token))
        assert b_summary.json()["draft"] == 0
