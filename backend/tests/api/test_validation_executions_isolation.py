"""Adversarial tests for the M11 Gated Safe Active Validation
orchestration layer.

Exercises the full HTTP path (route -> security dependency -> service
-> repository -> response) with real routers, a real in-memory SQLite
schema, and real AITargetService/TenantAssetService/
TenantSecurityConditionService collaborators — matching
test_authorizations_isolation.py's pattern. The M10 execution-policy
gate is a test double (`_SequencedPolicyPort`) implementing the exact
`ExecutionPolicyPort` seam the service depends on, which is the
legitimate boundary to fake for precise sequencing control (in
particular: forcing the two double-gate calls within one
`create_and_run()` invocation to answer differently, to prove the
"revoked between authorize and dispatch" gap is actually closed).
`TestRealM10PolicyIntegration` additionally wires the REAL M10
`SecurityAuthorizationService`/`ExecutionPolicyService` to prove the
integration is genuine, not merely mocked.

Real, owned local HTTP test servers back every test that needs a
successful network run. Never an external/unrelated internet target.

Covers M11 adversarial checklist items 1-14, 25-29, 32-48 (see
docs/M11_GATED_SAFE_ACTIVE_VALIDATION_REPORT.md for the full mapping).
Network-boundary/SSRF/redirect/DNS-rebinding items 15-24 are covered at
the adapter level in tests/unit/test_validation_execution_network_boundary.py.
"""

from __future__ import annotations

import http.server
import threading
from dataclasses import dataclass, field
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_auth_service,
    get_execution_policy_service,
    get_organization_service,
    get_security_authorization_service,
    get_token_service,
    get_user_status_service,
    get_validation_execution_service,
)
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.organizations import router as organizations_router
from redforge.api.v1.validation_executions import router as validation_executions_router
from redforge.application.ai_targets import AITargetService
from redforge.application.auth import AuthService
from redforge.application.authorization import ExecutionPolicyService, SecurityAuthorizationService
from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.organizations import OrganizationService
from redforge.application.security_conditions.service import TenantSecurityConditionService
from redforge.application.validation_execution import network_adapters
from redforge.application.validation_execution.execution_service import ValidationExecutionService
from redforge.domain.identity.value_objects import MembershipRole
from redforge.domain.validation_execution.value_objects import AddressClass
from redforge.infrastructure.audit.logger import InMemoryAuditLog
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (  # noqa: F401
    AIAssetModel,
    AITargetModel,
    MembershipModel,
    OrganizationModel,
    SecurityAuthorizationApprovalModel,
    SecurityAuthorizationDecisionModel,
    SecurityAuthorizationModel,
    SecurityAuthorizationScopeModel,
    SecurityConditionModel,
    UserModel,
    ValidationExecutionEventModel,
    ValidationExecutionModel,
    ValidationExecutionStepModel,
)
from redforge.infrastructure.database.repositories.membership_repository import (
    SqlAlchemyMembershipRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _allow_loopback_for_local_test_server(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test-only relaxation (see tests/unit/test_validation_execution_network_boundary.py
    for the same documented technique): production denies LOOPBACK by
    default (proven there); this suite's owned test server is
    necessarily loopback-bound, so LOOPBACK is allowed for the
    duration of every test in this module only. Never a production
    code path."""
    monkeypatch.setattr(
        network_adapters, "ALLOWED_ADDRESS_CLASSES",
        frozenset({AddressClass.PUBLIC, AddressClass.LOOPBACK}),
    )


# ─── Local HTTP test server (owned, in-process) ───────────────────────────────


_PORT = 18199


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/no-headers":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>ok</html>")
        else:
            self.send_response(200)
            self.send_header("Strict-Transport-Security", "max-age=1")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>ok</html>")

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture(scope="module", autouse=True)
def _local_server():
    server = http.server.HTTPServer(("127.0.0.1", _PORT), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


_TARGET_ENDPOINT = f"http://127.0.0.1:{_PORT}/"
_TARGET_ENDPOINT_NO_HEADERS = f"http://127.0.0.1:{_PORT}/no-headers"


# ─── Test doubles ──────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _Decision:
    decision: str
    decision_id: str
    reason_code: str


@dataclass
class _SequencedPolicyPort:
    """Legitimate fake for ExecutionPolicyPort (application/validation_execution/
    contracts.py) — precise, deterministic control over the double-gate
    sequence within one create_and_run() call, which a real M10 HTTP
    workflow cannot express (both evaluate() calls happen synchronously
    inside one method). Defaults to ALLOW when the queue is empty."""

    queue: list[_Decision] = field(default_factory=list)
    calls: list[dict[str, object]] = field(default_factory=list)

    def push_allow(self) -> None:
        self.queue.append(_Decision("allow", f"dec-{len(self.calls) + len(self.queue)}", "ok"))

    def push_deny(self, reason_code: str = "authorization_revoked") -> None:
        self.queue.append(_Decision("deny", f"dec-{len(self.calls) + len(self.queue)}", reason_code))

    def push_approval_required(self) -> None:
        self.queue.append(
            _Decision("approval_required", f"dec-{len(self.calls) + len(self.queue)}", "requires_approval"),
        )

    async def evaluate(
        self, *, organization_id: str, actor_user_id: str, action_class: str,
        entity_refs: list[tuple[str, str]],
    ) -> _Decision:
        self.calls.append({
            "organization_id": organization_id, "actor_user_id": actor_user_id,
            "action_class": action_class, "entity_refs": entity_refs,
        })
        if self.queue:
            return self.queue.pop(0)
        return _Decision("allow", f"dec-auto-{len(self.calls)}", "ok")


class _FakeOwnershipChecker:
    def __init__(self) -> None:
        self._owned: set[tuple[str, str, str]] = set()

    def register(self, organization_id: str, entity_type: str, entity_id: str) -> None:
        self._owned.add((organization_id, entity_type, entity_id))

    async def is_owned_by_organization(
        self, entity_type: str, entity_id: str, organization_id: str,
    ) -> bool:
        return (organization_id, entity_type, entity_id) in self._owned


class _AlwaysActiveUserStatusService:
    async def get_status(self, user_id: str) -> str:
        return "active"


# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def policy() -> _SequencedPolicyPort:
    return _SequencedPolicyPort()


@pytest.fixture
def ownership() -> _FakeOwnershipChecker:
    return _FakeOwnershipChecker()


@pytest.fixture
async def app(policy: _SequencedPolicyPort):
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    events = InMemoryEventPublisher()
    hasher = Argon2PasswordHasher(time_cost=1, memory_cost=16384, parallelism=1)
    tokens = JWTTokenService(secret_key="test-secret-key-that-is-long-enough-32!", access_ttl=3600)

    org_service = OrganizationService(factory, events, InMemoryAuditLog())
    auth_service = AuthService(factory, hasher, tokens, events)
    ai_target_service = AITargetService(factory, events)
    tenant_asset_service = TenantAssetService(factory)
    security_condition_service = TenantSecurityConditionService(factory)

    execution_service = ValidationExecutionService(
        factory, policy,  # type: ignore[arg-type]
        ai_target_service, tenant_asset_service, security_condition_service,
    )

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(organizations_router, prefix="/api/v1")
    test_app.include_router(validation_executions_router, prefix="/api/v1")

    test_app.dependency_overrides[get_organization_service] = lambda: org_service
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_auth_service] = lambda: auth_service
    test_app.dependency_overrides[get_token_service] = lambda: tokens
    test_app.dependency_overrides[get_validation_execution_service] = lambda: execution_service

    yield test_app, factory, ai_target_service
    await engine.dispose()


@pytest.fixture
async def client(app):
    test_app, _factory, _ai = app
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


async def _register_target(
    ai_target_service: AITargetService, organization_id: str, endpoint: str = _TARGET_ENDPOINT,
) -> str:
    dto = await ai_target_service.register(
        organization_id=organization_id, name="Owned Test Target", description="",
        target_type="ai_api", provider="custom", endpoint=endpoint,
    )
    return dto.id


async def _create_execution(client: AsyncClient, token: str, target_id: str) -> dict[str, Any]:
    resp = await client.post(
        "/api/v1/validation-executions", json={"target_id": target_id},
        headers=_auth_headers(token),
    )
    return resp.json() if resp.status_code == 201 else {"_status": resp.status_code, "_body": resp.text}


# ─── 1-2: Tenant isolation & non-disclosure ───────────────────────────────────


class TestTenantIsolation:
    async def test_tenant_a_execution_invisible_to_tenant_b(
        self, client: AsyncClient, app,
    ) -> None:
        _test_app, _factory, ai_target_service = app
        a_token, a_org, _ = await _create_org_and_select(client, "a1@test.com", "OrgA", "org-a1")
        b_token, _b_org, _ = await _create_org_and_select(client, "b1@test.com", "OrgB", "org-b1")

        target_id = await _register_target(ai_target_service, a_org)
        resp = await client.post(
            "/api/v1/validation-executions", json={"target_id": target_id},
            headers=_auth_headers(a_token),
        )
        assert resp.status_code == 201, resp.text
        execution_id = resp.json()["id"]

        b_get = await client.get(
            f"/api/v1/validation-executions/{execution_id}", headers=_auth_headers(b_token),
        )
        assert b_get.status_code == 404

        b_list = await client.get("/api/v1/validation-executions", headers=_auth_headers(b_token))
        assert b_list.json() == []

    async def test_guessed_foreign_execution_id_non_disclosing(self, client: AsyncClient) -> None:
        token, _org, _ = await _create_org_and_select(client, "a2@test.com", "OrgA", "org-a2")
        guessed_id = str(EntityId.generate())
        resp = await client.get(
            f"/api/v1/validation-executions/{guessed_id}", headers=_auth_headers(token),
        )
        assert resp.status_code == 404

    async def test_foreign_target_cannot_be_executed_against(
        self, client: AsyncClient, app,
    ) -> None:
        """A target that exists but belongs to a DIFFERENT organization
        cannot be executed against — AITargetService.get_by_id is
        itself org-scoped, so the target lookup during dispatch fails
        for the wrong tenant."""
        _test_app, _factory, ai_target_service = app
        _a_token, a_org, _ = await _create_org_and_select(client, "a3@test.com", "OrgA", "org-a3")
        b_token, b_org, _ = await _create_org_and_select(client, "b3@test.com", "OrgB", "org-b3")
        target_id = await _register_target(ai_target_service, a_org)

        resp = await client.post(
            "/api/v1/validation-executions", json={"target_id": target_id},
            headers=_auth_headers(b_token),
        )
        assert resp.status_code >= 400
        assert a_org != b_org


# ─── 3-6: Client cannot forge server-decided/arbitrary fields ─────────────────


class TestClientCannotSubmitArbitraryContent:
    async def test_unknown_profile_fails_safely(self, client: AsyncClient, app) -> None:
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "c1@test.com", "OrgA", "org-c1")
        target_id = await _register_target(ai_target_service, org)
        resp = await client.post(
            "/api/v1/validation-executions",
            json={"target_id": target_id, "profile": "arbitrary_scan_everything_v99"},
            headers=_auth_headers(token),
        )
        assert resp.status_code >= 400

    async def test_client_cannot_submit_steps(self, client: AsyncClient, app) -> None:
        """CreateExecutionRequest has no `steps` field at all — an
        extra client-submitted field is simply ignored by pydantic, not
        silently honored as an executable step list."""
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "c2@test.com", "OrgA", "org-c2")
        target_id = await _register_target(ai_target_service, org)
        resp = await client.post(
            "/api/v1/validation-executions",
            json={
                "target_id": target_id,
                "steps": [{"step_type": "shell_exec", "command": "rm -rf /"}],
                "ports": [22, 3389, 445],
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        step_types = {s["step_type"] for s in body["steps"]}
        assert "shell_exec" not in step_types

    async def test_no_arbitrary_execution_endpoint_exists(self, client: AsyncClient) -> None:
        token, _org, _ = await _create_org_and_select(client, "c3@test.com", "OrgA", "org-c3")
        for path in ("/api/v1/exec", "/api/v1/scan"):
            resp = await client.post(path, json={"command": "id"}, headers=_auth_headers(token))
            assert resp.status_code == 404
        # "/run-command" collides with the {execution_id} path parameter
        # pattern (FastAPI reports 405, not 404, for a matched path with
        # the wrong method) — what actually matters is that it never
        # executes anything, which the 405 itself already proves.
        collision_resp = await client.post(
            "/api/v1/validation-executions/run-command", json={"command": "id"},
            headers=_auth_headers(token),
        )
        assert collision_resp.status_code == 405

    async def test_missing_permission_denied(self, client: AsyncClient, app) -> None:
        """A VIEWER role has VALIDATIONS_READ but not VALIDATIONS_RUN."""
        _test_app, factory, ai_target_service = app
        _owner_token, org, _ = await _create_org_and_select(client, "c4@test.com", "OrgA", "org-c4")
        target_id = await _register_target(ai_target_service, org)
        viewer_token = await _add_member(factory, client, org, "viewer4@test.com", MembershipRole.VIEWER)
        resp = await client.post(
            "/api/v1/validation-executions", json={"target_id": target_id},
            headers=_auth_headers(viewer_token),
        )
        assert resp.status_code == 403


# ─── 7-9: Policy gate — DENY / APPROVAL_REQUIRED zero network calls ───────────


class TestPolicyGateBlocksExecution:
    async def test_deny_decision_produces_zero_steps(
        self, client: AsyncClient, app, policy: _SequencedPolicyPort,
    ) -> None:
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "d1@test.com", "OrgA", "org-d1")
        target_id = await _register_target(ai_target_service, org)
        policy.push_deny("no_authorization_found")

        body = await _create_execution(client, token, target_id)
        assert body["status"] == "denied"
        assert body["steps"] == []
        assert body["policy_reason_code"] == "no_authorization_found"

    async def test_approval_required_decision_produces_zero_steps(
        self, client: AsyncClient, app, policy: _SequencedPolicyPort,
    ) -> None:
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "d2@test.com", "OrgA", "org-d2")
        target_id = await _register_target(ai_target_service, org)
        policy.push_approval_required()

        body = await _create_execution(client, token, target_id)
        assert body["status"] == "denied"
        assert body["steps"] == []

    async def test_revoked_between_authorize_and_dispatch_blocks_dispatch(
        self, client: AsyncClient, app, policy: _SequencedPolicyPort,
    ) -> None:
        """The second, time-of-use policy check (immediately before
        step dispatch) is what this test proves is real: ALLOW on the
        first check, DENY on the second — zero steps must ever run."""
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "d3@test.com", "OrgA", "org-d3")
        target_id = await _register_target(ai_target_service, org)
        policy.push_allow()
        policy.push_deny("authorization_revoked")

        body = await _create_execution(client, token, target_id)
        assert body["status"] == "denied"
        assert body["steps"] == []
        assert body["policy_reason_code"] == "authorization_revoked"
        assert len(policy.calls) == 2

    async def test_policy_evaluated_with_correct_action_class_and_entity_ref(
        self, client: AsyncClient, app, policy: _SequencedPolicyPort,
    ) -> None:
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "d4@test.com", "OrgA", "org-d4")
        target_id = await _register_target(ai_target_service, org)

        await _create_execution(client, token, target_id)
        assert policy.calls[0]["action_class"] == "active_validation"
        assert policy.calls[0]["entity_refs"] == [("ai_target", target_id)]


# ─── 10-12: Unsupported target / malformed URL fails safely ──────────────────


class TestPreflightFailures:
    async def test_target_with_userinfo_in_url_fails_preflight(
        self, client: AsyncClient, app,
    ) -> None:
        """AITarget.EndpointUrl only enforces an http(s):// scheme (see
        domain/ai_targets/value_objects.py) — it does not reject
        userinfo, so a target CAN legitimately be registered with one.
        M11's stricter target_normalizer is the layer that must still
        catch it before any network activity."""
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "e1@test.com", "OrgA", "org-e1")
        target_id = await _register_target(
            ai_target_service, org, endpoint="http://user:pass@example.com/",
        )

        body = await _create_execution(client, token, target_id)
        assert body["status"] == "failed"
        assert body["steps"] == []
        assert "target normalization" in body["failure_reason"]

    async def test_nonexistent_target_id_fails(self, client: AsyncClient) -> None:
        token, _org, _ = await _create_org_and_select(client, "e2@test.com", "OrgA", "org-e2")
        resp = await client.post(
            "/api/v1/validation-executions",
            json={"target_id": str(EntityId.generate())},
            headers=_auth_headers(token),
        )
        assert resp.status_code >= 400


# ─── 13-16: Real network run + condition ingestion + dedup ───────────────────


class TestRealNetworkExecutionAndConditionSemantics:
    async def test_full_pipeline_completes_and_ingests_conditions(
        self, client: AsyncClient, app,
    ) -> None:
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "f1@test.com", "OrgA", "org-f1")
        target_id = await _register_target(ai_target_service, org, endpoint=_TARGET_ENDPOINT_NO_HEADERS)

        body = await _create_execution(client, token, target_id)
        assert body["status"] in ("completed", "partially_completed")
        step_types = [s["step_type"] for s in body["steps"]]
        assert step_types == [
            "dns_resolution", "tcp_connectivity", "http_metadata",
            "http_security_headers", "service_reachability",
        ]
        assert all(s["status"] == "completed" for s in body["steps"])

        headers_step = next(s for s in body["steps"] if s["step_type"] == "http_security_headers")
        rules = {e["value"] for e in headers_step["evidence"]}
        assert "MISSING_CSP_HEADER" in rules
        assert "MISSING_X_CONTENT_TYPE_OPTIONS_HEADER" in rules

    async def test_tcp_open_alone_produces_no_finding(self, client: AsyncClient, app) -> None:
        """A bare TCP connect (or an HTTP 200) is a connectivity
        observation, never fabricated into a Finding — only the
        deterministic header-rule evaluation ever produces a
        SecurityCondition."""
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "f2@test.com", "OrgA", "org-f2")
        target_id = await _register_target(ai_target_service, org)

        body = await _create_execution(client, token, target_id)
        tcp_step = next(s for s in body["steps"] if s["step_type"] == "tcp_connectivity")
        assert tcp_step["status"] == "completed"
        assert not any(e["label"] == "finding" for e in tcp_step["evidence"])

    async def test_repeated_execution_does_not_duplicate_condition(
        self, client: AsyncClient, app,
    ) -> None:
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "f3@test.com", "OrgA", "org-f3")
        target_id = await _register_target(ai_target_service, org, endpoint=_TARGET_ENDPOINT_NO_HEADERS)

        await _create_execution(client, token, target_id)
        await _create_execution(client, token, target_id)

        from redforge.application.security_conditions.service import TenantSecurityConditionService

        condition_service = TenantSecurityConditionService(_factory)
        conditions = await condition_service.list_for_org(org, source_category="active_validation")
        csp_conditions = [c for c in conditions if c.stable_rule_id == "MISSING_CSP_HEADER"]
        assert len(csp_conditions) == 1

    async def test_condition_has_correct_source_category_and_evidence_state(
        self, client: AsyncClient, app,
    ) -> None:
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "f4@test.com", "OrgA", "org-f4")
        target_id = await _register_target(ai_target_service, org, endpoint=_TARGET_ENDPOINT_NO_HEADERS)

        await _create_execution(client, token, target_id)

        condition_service = TenantSecurityConditionService(_factory)
        conditions = await condition_service.list_for_org(org, source_category="active_validation")
        assert conditions
        for c in conditions:
            assert c.source_category == "active_validation"
            assert c.evidence_state == "validated"

    async def test_result_endpoint_is_crisp_and_truthful(self, client: AsyncClient, app) -> None:
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "f5@test.com", "OrgA", "org-f5")
        target_id = await _register_target(ai_target_service, org)

        create_body = await _create_execution(client, token, target_id)
        execution_id = create_body["id"]
        resp = await client.get(
            f"/api/v1/validation-executions/{execution_id}/result", headers=_auth_headers(token),
        )
        assert resp.status_code == 200, resp.text
        result = resp.json()
        assert result["tcp_reachable"] is True
        assert result["application_layer_validated"] is True
        assert result["validation_basis"] == "http"
        assert result["failed_steps"] == []


# ─── 17-18: Secrets never persisted ────────────────────────────────────────────


class TestSecretsNeverPersisted:
    async def test_authorization_bearer_token_never_appears_in_events_or_steps(
        self, client: AsyncClient, app,
    ) -> None:
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "g1@test.com", "OrgA", "org-g1")
        target_id = await _register_target(ai_target_service, org)

        create_body = await _create_execution(client, token, target_id)
        execution_id = create_body["id"]
        serialized_steps = str(create_body["steps"])
        assert token not in serialized_steps
        assert "authorization" not in serialized_steps.lower()

        events_resp = await client.get(
            f"/api/v1/validation-executions/{execution_id}/events", headers=_auth_headers(token),
        )
        assert token not in str(events_resp.json())


# ─── 19-21: Cancellation ───────────────────────────────────────────────────────


class TestCancellation:
    async def test_cancel_completed_execution_is_rejected_not_silently_resurrected(
        self, client: AsyncClient, app,
    ) -> None:
        """A terminal execution rejects cancellation outright (422 —
        InvalidExecutionTransitionError) rather than silently
        succeeding as a no-op: fail-closed instead of returning a
        misleading 200 for a request that changes nothing."""
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "h1@test.com", "OrgA", "org-h1")
        target_id = await _register_target(ai_target_service, org)
        create_body = await _create_execution(client, token, target_id)
        assert create_body["status"] in ("completed", "partially_completed")
        execution_id = create_body["id"]

        cancel_resp = await client.post(
            f"/api/v1/validation-executions/{execution_id}/cancel", headers=_auth_headers(token),
        )
        assert cancel_resp.status_code == 422

        unchanged = await client.get(
            f"/api/v1/validation-executions/{execution_id}", headers=_auth_headers(token),
        )
        assert unchanged.json()["status"] == create_body["status"]

    async def test_cancel_foreign_execution_is_denied(self, client: AsyncClient, app) -> None:
        _test_app, _factory, ai_target_service = app
        a_token, a_org, _ = await _create_org_and_select(client, "h2@test.com", "OrgA", "org-h2")
        b_token, _b_org, _ = await _create_org_and_select(client, "hb2@test.com", "OrgB", "org-hb2")
        target_id = await _register_target(ai_target_service, a_org)
        create_body = await _create_execution(client, a_token, target_id)

        resp = await client.post(
            f"/api/v1/validation-executions/{create_body['id']}/cancel",
            headers=_auth_headers(b_token),
        )
        assert resp.status_code == 404

    async def test_cancel_requires_run_permission_not_just_read(
        self, client: AsyncClient, app,
    ) -> None:
        _test_app, factory, ai_target_service = app
        owner_token, org, _ = await _create_org_and_select(client, "h3@test.com", "OrgA", "org-h3")
        target_id = await _register_target(ai_target_service, org)
        create_body = await _create_execution(client, owner_token, target_id)
        viewer_token = await _add_member(factory, client, org, "viewer3@test.com", MembershipRole.VIEWER)

        resp = await client.post(
            f"/api/v1/validation-executions/{create_body['id']}/cancel",
            headers=_auth_headers(viewer_token),
        )
        assert resp.status_code == 403


# ─── 22-24: Events bounded, ordered, and live ─────────────────────────────────


class TestEventsBoundedAndOrdered:
    async def test_events_persisted_in_strictly_increasing_sequence(
        self, client: AsyncClient, app,
    ) -> None:
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "i1@test.com", "OrgA", "org-i1")
        target_id = await _register_target(ai_target_service, org)
        create_body = await _create_execution(client, token, target_id)

        resp = await client.get(
            f"/api/v1/validation-executions/{create_body['id']}/events",
            headers=_auth_headers(token),
        )
        events = resp.json()
        sequences = [e["sequence"] for e in events]
        assert sequences == sorted(sequences)
        assert len(sequences) == len(set(sequences))
        assert events[0]["event_type"] == "execution_created"

    async def test_events_after_sequence_filter_works(self, client: AsyncClient, app) -> None:
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "i2@test.com", "OrgA", "org-i2")
        target_id = await _register_target(ai_target_service, org)
        create_body = await _create_execution(client, token, target_id)
        execution_id = create_body["id"]

        all_events = (await client.get(
            f"/api/v1/validation-executions/{execution_id}/events", headers=_auth_headers(token),
        )).json()
        midpoint = all_events[len(all_events) // 2]["sequence"]

        filtered = (await client.get(
            f"/api/v1/validation-executions/{execution_id}/events",
            params={"after_sequence": midpoint}, headers=_auth_headers(token),
        )).json()
        assert all(e["sequence"] > midpoint for e in filtered)

    async def test_events_invisible_to_foreign_tenant(self, client: AsyncClient, app) -> None:
        """The events query is itself organization_id-scoped at the SQL
        WHERE-clause level (see SqlAlchemyExecutionEventRepository.
        list_for_execution) — a foreign tenant gets a 200 with an empty
        list, never any of the real tenant's event data. Zero
        disclosure, even though the status code differs from the
        404 the {execution_id} detail route uses."""
        _test_app, _factory, ai_target_service = app
        a_token, a_org, _ = await _create_org_and_select(client, "i3@test.com", "OrgA", "org-i3")
        b_token, _b_org, _ = await _create_org_and_select(client, "ib3@test.com", "OrgB", "org-ib3")
        target_id = await _register_target(ai_target_service, a_org)
        create_body = await _create_execution(client, a_token, target_id)

        resp = await client.get(
            f"/api/v1/validation-executions/{create_body['id']}/events",
            headers=_auth_headers(b_token),
        )
        assert resp.status_code == 200
        assert resp.json() == []


# ─── 25-27: Restart persistence, summary, listing ─────────────────────────────


class TestRestartPersistenceAndSummary:
    async def test_execution_history_survives_a_fresh_service_instance(
        self, client: AsyncClient, app, policy: _SequencedPolicyPort,
    ) -> None:
        """Simulates a process restart: a brand-new ValidationExecutionService
        instance (same DB) must read back the exact same execution."""
        _test_app, factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "j1@test.com", "OrgA", "org-j1")
        target_id = await _register_target(ai_target_service, org)
        create_body = await _create_execution(client, token, target_id)

        fresh_service = ValidationExecutionService(
            factory, policy,  # type: ignore[arg-type]
            ai_target_service, TenantAssetService(factory), TenantSecurityConditionService(factory),
        )
        reloaded = await fresh_service.get_by_id(org, create_body["id"])
        assert reloaded.id == create_body["id"]
        assert reloaded.status == create_body["status"]
        assert len(reloaded.steps) == len(create_body["steps"])

    async def test_summary_counts_are_backend_derived(self, client: AsyncClient, app) -> None:
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "j2@test.com", "OrgA", "org-j2")
        target_id = await _register_target(ai_target_service, org)
        await _create_execution(client, token, target_id)

        resp = await client.get("/api/v1/validation-executions/summary", headers=_auth_headers(token))
        assert resp.status_code == 200
        summary = resp.json()
        assert sum(summary.values()) == 1

    async def test_list_filter_by_status(self, client: AsyncClient, app, policy) -> None:
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "j3@test.com", "OrgA", "org-j3")
        target_id = await _register_target(ai_target_service, org)
        policy.push_deny()
        await _create_execution(client, token, target_id)

        resp = await client.get(
            "/api/v1/validation-executions", params={"status": "denied"},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        assert all(e["status"] == "denied" for e in resp.json())


# ─── 28-29: No direct adapter invocation from router, execution boundary ─────


class TestArchitecturalBoundaries:
    async def test_router_module_never_imports_network_adapters_directly(self) -> None:
        import inspect

        import redforge.api.v1.validation_executions as router_module

        source = inspect.getsource(router_module)
        assert "network_adapters" not in source
        assert "import ssl" not in source
        assert "import socket" not in source

    async def test_every_execution_requires_its_own_fresh_policy_decision(
        self, client: AsyncClient, app, policy: _SequencedPolicyPort,
    ) -> None:
        """Two separate create_and_run() calls for the same target must
        each independently invoke the policy gate — no caching or
        reuse of a prior ALLOW decision across executions."""
        _test_app, _factory, ai_target_service = app
        token, org, _ = await _create_org_and_select(client, "k1@test.com", "OrgA", "org-k1")
        target_id = await _register_target(ai_target_service, org)

        await _create_execution(client, token, target_id)
        calls_after_first = len(policy.calls)
        await _create_execution(client, token, target_id)
        assert len(policy.calls) == calls_after_first * 2


# ─── Real M10 integration proof (not a fake port) ─────────────────────────────


class TestRealM10PolicyIntegration:
    """Proves the M10<->M11 integration is genuine: a real
    SecurityAuthorizationService + ExecutionPolicyService, driven
    through the actual create/submit/approve HTTP lifecycle, is what
    decides ALLOW here — not a test double."""

    @pytest.fixture
    async def real_policy_app(self):
        engine = create_async_engine("sqlite+aiosqlite://", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        events = InMemoryEventPublisher()
        audit = InMemoryAuditLog()
        hasher = Argon2PasswordHasher(time_cost=1, memory_cost=16384, parallelism=1)
        tokens = JWTTokenService(secret_key="test-secret-key-that-is-long-enough-32!", access_ttl=3600)
        ownership = _FakeOwnershipChecker()

        org_service = OrganizationService(factory, events, audit)
        auth_service = AuthService(factory, hasher, tokens, events)
        ai_target_service = AITargetService(factory, events)
        authorization_service = SecurityAuthorizationService(
            factory, events, audit, ownership_checker=ownership,
        )
        real_policy_service = ExecutionPolicyService(factory, ownership_checker=ownership)
        execution_service = ValidationExecutionService(
            factory, real_policy_service,  # type: ignore[arg-type]
            ai_target_service, TenantAssetService(factory), TenantSecurityConditionService(factory),
        )

        from redforge.api.v1.authorizations import router as authorizations_router

        test_app = FastAPI()
        test_app.add_middleware(ErrorHandlerMiddleware)
        test_app.include_router(auth_router, prefix="/api/v1")
        test_app.include_router(organizations_router, prefix="/api/v1")
        test_app.include_router(authorizations_router, prefix="/api/v1")
        test_app.include_router(validation_executions_router, prefix="/api/v1")
        test_app.dependency_overrides[get_organization_service] = lambda: org_service
        test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
        test_app.dependency_overrides[get_auth_service] = lambda: auth_service
        test_app.dependency_overrides[get_token_service] = lambda: tokens
        test_app.dependency_overrides[get_validation_execution_service] = lambda: execution_service
        test_app.dependency_overrides[get_security_authorization_service] = lambda: authorization_service
        test_app.dependency_overrides[get_execution_policy_service] = lambda: real_policy_service

        transport = ASGITransport(app=test_app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac, factory, ai_target_service, ownership
        await engine.dispose()

    async def test_no_authorization_at_all_denies_real_execution(self, real_policy_app) -> None:
        client, _factory, ai_target_service, ownership = real_policy_app
        token, org, _ = await _create_org_and_select(client, "m1@test.com", "OrgA", "org-m1")
        target_id = await _register_target(ai_target_service, org)
        ownership.register(org, "ai_target", target_id)

        body = await _create_execution(client, token, target_id)
        assert body["status"] == "denied"
        assert body["steps"] == []

    async def test_real_approved_authorization_allows_real_execution(self, real_policy_app) -> None:
        client, factory, ai_target_service, ownership = real_policy_app
        from datetime import UTC, datetime, timedelta

        token, org, _ = await _create_org_and_select(client, "m2@test.com", "OrgA", "org-m2")
        target_id = await _register_target(ai_target_service, org)
        ownership.register(org, "ai_target", target_id)

        start = datetime.now(UTC) - timedelta(minutes=1)
        end = start + timedelta(hours=24)
        create_resp = await client.post(
            "/api/v1/authorizations",
            json={
                "action_classes": ["active_validation"],
                "scope": [{"entity_type": "ai_target", "entity_id": target_id}],
                "valid_from": start.isoformat(), "valid_until": end.isoformat(),
            },
            headers=_auth_headers(token),
        )
        assert create_resp.status_code == 201, create_resp.text
        auth_id = create_resp.json()["id"]
        submit_resp = await client.post(
            f"/api/v1/authorizations/{auth_id}/submit", headers=_auth_headers(token),
        )
        assert submit_resp.status_code == 200, submit_resp.text

        approver_token = await _add_member(
            factory, client, org, "approver-m2@test.com", MembershipRole.ADMIN,
        )
        approve_resp = await client.post(
            f"/api/v1/authorizations/{auth_id}/approve", headers=_auth_headers(approver_token),
        )
        assert approve_resp.status_code == 200, approve_resp.text

        body = await _create_execution(client, token, target_id)
        assert body["status"] in ("completed", "partially_completed")
        assert len(body["steps"]) > 0

    async def test_revoked_real_authorization_blocks_new_execution(self, real_policy_app) -> None:
        client, factory, ai_target_service, ownership = real_policy_app
        from datetime import UTC, datetime, timedelta

        token, org, _ = await _create_org_and_select(client, "m3@test.com", "OrgA", "org-m3")
        target_id = await _register_target(ai_target_service, org)
        ownership.register(org, "ai_target", target_id)

        start = datetime.now(UTC) - timedelta(minutes=1)
        end = start + timedelta(hours=24)
        create_resp = await client.post(
            "/api/v1/authorizations",
            json={
                "action_classes": ["active_validation"],
                "scope": [{"entity_type": "ai_target", "entity_id": target_id}],
                "valid_from": start.isoformat(), "valid_until": end.isoformat(),
            },
            headers=_auth_headers(token),
        )
        auth_id = create_resp.json()["id"]
        await client.post(f"/api/v1/authorizations/{auth_id}/submit", headers=_auth_headers(token))
        approver_token = await _add_member(
            factory, client, org, "approver-m3@test.com", MembershipRole.ADMIN,
        )
        await client.post(
            f"/api/v1/authorizations/{auth_id}/approve", headers=_auth_headers(approver_token),
        )
        revoke_resp = await client.post(
            f"/api/v1/authorizations/{auth_id}/revoke", headers=_auth_headers(approver_token),
            json={"reason": "test revoke"},
        )
        assert revoke_resp.status_code == 200, revoke_resp.text

        body = await _create_execution(client, token, target_id)
        assert body["status"] == "denied"
        assert body["steps"] == []
