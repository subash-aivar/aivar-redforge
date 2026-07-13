"""Adversarial isolation tests for the Continuous Validation Scheduler,
Security Drift Detection & Revalidation Engine REST API (M14).

Exercises the full HTTP path (route -> security dependency -> service
-> processor -> repository -> response) with real routers, a real
in-memory SQLite schema, a real owned local HTTP lab target, and the
real ContinuousValidationProcessor/ValidationExecutionService chain —
matching test_validation_executions_isolation.py's established pattern.
The M10 execution-policy gate uses the same `_SequencedPolicyPort` test
double that file uses (the legitimate boundary to fake for precise
sequencing control); everything else is real.
"""

from __future__ import annotations

import http.server
import threading
from dataclasses import dataclass, field

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_auth_service,
    get_continuous_validation_policy_service,
    get_continuous_validation_processor,
    get_effective_access_service,
    get_organization_service,
    get_security_drift_service,
    get_token_service,
    get_user_status_service,
)
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.continuous_validation import router as continuous_validation_router
from redforge.api.v1.organizations import router as organizations_router
from redforge.application.ai_targets import AITargetService
from redforge.application.auth import AuthService
from redforge.application.continuous_validation.drift_service import SecurityDriftService
from redforge.application.continuous_validation.policy_service import (
    ContinuousValidationPolicyService,
)
from redforge.application.continuous_validation.processor import ContinuousValidationProcessor
from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.organizations import OrganizationService
from redforge.application.security_conditions.service import TenantSecurityConditionService
from redforge.application.security_correlation.rules import CorrelationRuleRegistry
from redforge.application.security_correlation.service import TenantSecurityCorrelationService
from redforge.application.validation_execution import network_adapters
from redforge.application.validation_execution.adaptive_rules import default_adaptive_rule_registry
from redforge.application.validation_execution.execution_service import ValidationExecutionService
from redforge.application.validation_execution.protocol_validators import (
    default_protocol_validator_registry,
)
from redforge.domain.identity.value_objects import MembershipRole
from redforge.domain.validation_execution.value_objects import AddressClass
from redforge.infrastructure.audit.logger import InMemoryAuditLog
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (  # noqa: F401
    AIAssetModel,
    AITargetModel,
    ContinuousValidationPolicyModel,
    MembershipModel,
    OrganizationModel,
    SecurityConditionModel,
    SecurityCorrelationConditionModel,
    SecurityCorrelationEntityModel,
    SecurityCorrelationModel,
    SecurityDriftEventModel,
    SecurityGraphEdgeModel,
    SecurityGraphNodeModel,
    UserModel,
    ValidationExecutionEventModel,
    ValidationExecutionModel,
    ValidationExecutionStepModel,
    ValidationStateSnapshotModel,
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
    monkeypatch.setattr(
        network_adapters, "ALLOWED_ADDRESS_CLASSES",
        frozenset({AddressClass.PUBLIC, AddressClass.LOOPBACK}),
    )


# ─── Local HTTP test server (owned, in-process) ───────────────────────────────

_PORT = 18299
_STATE = {"secure_headers": True}


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        if _STATE["secure_headers"]:
            self.send_header("Strict-Transport-Security", "max-age=1")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
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


@pytest.fixture(autouse=True)
def _reset_headers_state():
    _STATE["secure_headers"] = True
    yield
    _STATE["secure_headers"] = True


_TARGET_ENDPOINT = f"http://127.0.0.1:{_PORT}/"


# ─── Test doubles ──────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _Decision:
    decision: str
    decision_id: str
    reason_code: str


@dataclass
class _AlwaysAllowPolicyPort:
    calls: list[dict[str, object]] = field(default_factory=list)

    async def evaluate(
        self, *, organization_id: str, actor_user_id: str, action_class: str,
        entity_refs: list[tuple[str, str]],
    ) -> _Decision:
        self.calls.append({"organization_id": organization_id, "actor_user_id": actor_user_id})
        return _Decision("allow", f"dec-{len(self.calls)}", "ok")


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


# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def policy_port() -> _AlwaysAllowPolicyPort:
    return _AlwaysAllowPolicyPort()


@pytest.fixture
async def app(policy_port: _AlwaysAllowPolicyPort):
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
    condition_service = TenantSecurityConditionService(factory)
    correlation_registry = CorrelationRuleRegistry()
    correlation_service = TenantSecurityCorrelationService(factory, correlation_registry)

    execution_service = ValidationExecutionService(
        factory, policy_port,  # type: ignore[arg-type]
        ai_target_service, tenant_asset_service, condition_service,
        default_adaptive_rule_registry(), correlation_service,
        default_protocol_validator_registry(),
    )
    policy_service = ContinuousValidationPolicyService(factory, ai_target_service)
    drift_service = SecurityDriftService(factory)
    processor = ContinuousValidationProcessor(
        factory, execution_service, ai_target_service, tenant_asset_service,
        condition_service, correlation_service, drift_service,
    )

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(organizations_router, prefix="/api/v1")
    test_app.include_router(continuous_validation_router, prefix="/api/v1")

    test_app.dependency_overrides[get_organization_service] = lambda: org_service
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_effective_access_service] = lambda: _NoOpEffectiveAccessService()
    test_app.dependency_overrides[get_auth_service] = lambda: auth_service
    test_app.dependency_overrides[get_token_service] = lambda: tokens
    test_app.dependency_overrides[get_continuous_validation_policy_service] = (
        lambda: policy_service
    )
    test_app.dependency_overrides[get_continuous_validation_processor] = lambda: processor
    test_app.dependency_overrides[get_security_drift_service] = lambda: drift_service

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
    return str(dto.id)


# ─── Create / validation ────────────────────────────────────────────────────────


async def test_create_policy_in_draft(client, app) -> None:
    _test_app, _factory, ai_target_service = app
    token, org_id, _user_id = await _create_org_and_select(
        client, "owner1@example.com", "Org One", "org-one",
    )
    target_id = await _register_target(ai_target_service, org_id)

    resp = await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_id, "profile": "safe_active_baseline_v1", "cadence": "hourly"},
        headers=_auth_headers(token),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["lifecycle"] == "draft"
    assert body["next_due_at"] is None
    assert body["cadence"] == "hourly"


async def test_create_policy_unknown_profile_rejected(client, app) -> None:
    _test_app, _factory, ai_target_service = app
    token, org_id, _user_id = await _create_org_and_select(
        client, "owner2@example.com", "Org Two", "org-two",
    )
    target_id = await _register_target(ai_target_service, org_id)

    resp = await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_id, "profile": "not_a_real_profile", "cadence": "hourly"},
        headers=_auth_headers(token),
    )
    assert resp.status_code == 422, resp.text


async def test_create_policy_unknown_cadence_rejected(client, app) -> None:
    _test_app, _factory, ai_target_service = app
    token, org_id, _user_id = await _create_org_and_select(
        client, "owner3@example.com", "Org Three", "org-three",
    )
    target_id = await _register_target(ai_target_service, org_id)

    resp = await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_id, "profile": "safe_active_baseline_v1", "cadence": "every_minute"},
        headers=_auth_headers(token),
    )
    assert resp.status_code == 422, resp.text


async def test_create_policy_against_non_owned_target_rejected(client, app) -> None:
    _test_app, _factory, ai_target_service = app
    token_a, _org_a, _u1 = await _create_org_and_select(
        client, "ownera@example.com", "Org A", "org-a-cv",
    )
    _token_b, org_b, _u2 = await _create_org_and_select(
        client, "ownerb@example.com", "Org B", "org-b-cv",
    )
    target_in_b = await _register_target(ai_target_service, org_b)

    resp = await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_in_b, "profile": "safe_active_baseline_v1", "cadence": "hourly"},
        headers=_auth_headers(token_a),
    )
    assert resp.status_code == 404, resp.text


# ─── Lifecycle ──────────────────────────────────────────────────────────────────


async def test_activate_pause_resume_disable_roundtrip(client, app) -> None:
    _test_app, _factory, ai_target_service = app
    token, org_id, _user_id = await _create_org_and_select(
        client, "lifecycle@example.com", "Lifecycle Org", "lifecycle-org",
    )
    target_id = await _register_target(ai_target_service, org_id)
    create_resp = await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_id, "profile": "safe_active_baseline_v1", "cadence": "hourly"},
        headers=_auth_headers(token),
    )
    policy_id = create_resp.json()["id"]

    activate_resp = await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/activate",
        headers=_auth_headers(token),
    )
    assert activate_resp.status_code == 200, activate_resp.text
    assert activate_resp.json()["lifecycle"] == "active"
    assert activate_resp.json()["next_due_at"] is not None

    pause_resp = await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/pause",
        headers=_auth_headers(token),
    )
    assert pause_resp.json()["lifecycle"] == "paused"

    resume_resp = await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/resume",
        headers=_auth_headers(token),
    )
    assert resume_resp.json()["lifecycle"] == "active"

    disable_resp = await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/disable",
        headers=_auth_headers(token),
    )
    assert disable_resp.json()["lifecycle"] == "disabled"


async def test_disabled_policy_cannot_be_reactivated(client, app) -> None:
    _test_app, _factory, ai_target_service = app
    token, org_id, _user_id = await _create_org_and_select(
        client, "disable1@example.com", "Disable Org", "disable-org",
    )
    target_id = await _register_target(ai_target_service, org_id)
    create_resp = await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_id, "cadence": "hourly"},
        headers=_auth_headers(token),
    )
    policy_id = create_resp.json()["id"]
    await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/activate",
        headers=_auth_headers(token),
    )
    await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/disable",
        headers=_auth_headers(token),
    )

    reactivate_resp = await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/activate",
        headers=_auth_headers(token),
    )
    assert reactivate_resp.status_code == 422, reactivate_resp.text


async def test_activate_twice_rejected(client, app) -> None:
    _test_app, _factory, ai_target_service = app
    token, org_id, _user_id = await _create_org_and_select(
        client, "activatetwice@example.com", "Activate Twice Org", "activate-twice-org",
    )
    target_id = await _register_target(ai_target_service, org_id)
    create_resp = await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_id, "cadence": "hourly"},
        headers=_auth_headers(token),
    )
    policy_id = create_resp.json()["id"]
    await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/activate",
        headers=_auth_headers(token),
    )
    second = await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/activate",
        headers=_auth_headers(token),
    )
    assert second.status_code == 422, second.text


# ─── run-now ────────────────────────────────────────────────────────────────────


async def test_run_now_produces_on_demand_trigger(client, app) -> None:
    _test_app, _factory, ai_target_service = app
    token, org_id, _user_id = await _create_org_and_select(
        client, "runnow@example.com", "Run Now Org", "run-now-org",
    )
    target_id = await _register_target(ai_target_service, org_id)
    create_resp = await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_id, "cadence": "hourly"},
        headers=_auth_headers(token),
    )
    policy_id = create_resp.json()["id"]

    run_resp = await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/run-now",
        headers=_auth_headers(token),
    )
    assert run_resp.status_code == 200, run_resp.text
    body = run_resp.json()
    assert body["trigger"] == "on_demand"
    assert body["status"] == "completed"


async def test_run_now_against_disabled_policy_rejected(client, app) -> None:
    _test_app, _factory, ai_target_service = app
    token, org_id, _user_id = await _create_org_and_select(
        client, "runnowdisabled@example.com", "Run Now Disabled Org", "run-now-disabled-org",
    )
    target_id = await _register_target(ai_target_service, org_id)
    create_resp = await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_id, "cadence": "hourly"},
        headers=_auth_headers(token),
    )
    policy_id = create_resp.json()["id"]
    await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/activate",
        headers=_auth_headers(token),
    )
    await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/disable",
        headers=_auth_headers(token),
    )

    run_resp = await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/run-now",
        headers=_auth_headers(token),
    )
    assert run_resp.status_code == 422, run_resp.text


async def test_run_now_never_advances_next_due_at(client, app) -> None:
    _test_app, _factory, ai_target_service = app
    token, org_id, _user_id = await _create_org_and_select(
        client, "runnownoadvance@example.com", "No Advance Org", "no-advance-org",
    )
    target_id = await _register_target(ai_target_service, org_id)
    create_resp = await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_id, "cadence": "hourly"},
        headers=_auth_headers(token),
    )
    policy_id = create_resp.json()["id"]
    activate_resp = await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/activate",
        headers=_auth_headers(token),
    )
    original_due = activate_resp.json()["next_due_at"]

    await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/run-now",
        headers=_auth_headers(token),
    )
    get_resp = await client.get(
        f"/api/v1/continuous-validation/policies/{policy_id}", headers=_auth_headers(token),
    )
    assert get_resp.json()["next_due_at"] == original_due


# ─── Drift lifecycle (STATE A/B/C) ──────────────────────────────────────────────


async def test_drift_lifecycle_appear_resolve_reactivate(client, app) -> None:
    _test_app, _factory, ai_target_service = app
    token, org_id, _user_id = await _create_org_and_select(
        client, "driftlifecycle@example.com", "Drift Org", "drift-org",
    )
    target_id = await _register_target(ai_target_service, org_id)
    create_resp = await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_id, "cadence": "hourly"},
        headers=_auth_headers(token),
    )
    policy_id = create_resp.json()["id"]
    await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/activate",
        headers=_auth_headers(token),
    )

    # STATE A: baseline (headers already present per _reset_headers_state).
    run_a = await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/run-now",
        headers=_auth_headers(token),
    )
    assert run_a.status_code == 200, run_a.text
    drift_a = await client.get(
        f"/api/v1/continuous-validation/policies/{policy_id}/drift",
        headers=_auth_headers(token),
    )
    assert drift_a.json() == []  # no prior baseline -> zero drift

    # STATE B: mutate lab truth -> headers missing -> conditions appear.
    _STATE["secure_headers"] = False
    run_b = await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/run-now",
        headers=_auth_headers(token),
    )
    assert run_b.status_code == 200, run_b.text
    drift_b = await client.get(
        f"/api/v1/continuous-validation/policies/{policy_id}/drift",
        headers=_auth_headers(token),
    )
    categories_b = {e["category"] for e in drift_b.json()}
    assert "condition_appeared" in categories_b

    # STATE C: restore headers -> conditions resolve.
    _STATE["secure_headers"] = True
    run_c = await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/run-now",
        headers=_auth_headers(token),
    )
    assert run_c.status_code == 200, run_c.text
    drift_c = await client.get(
        f"/api/v1/continuous-validation/policies/{policy_id}/drift",
        headers=_auth_headers(token),
    )
    categories_c = {e["category"] for e in drift_c.json()}
    assert "condition_resolved" in categories_c

    # Identical rerun -> zero NEW drift events.
    drift_count_before = len(drift_c.json())
    run_d = await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/run-now",
        headers=_auth_headers(token),
    )
    assert run_d.status_code == 200, run_d.text
    drift_d = await client.get(
        f"/api/v1/continuous-validation/policies/{policy_id}/drift",
        headers=_auth_headers(token),
    )
    assert len(drift_d.json()) == drift_count_before

    # Change feed reflects the same events org-wide.
    feed_resp = await client.get(
        "/api/v1/continuous-validation/change-feed", headers=_auth_headers(token),
    )
    assert feed_resp.status_code == 200, feed_resp.text
    assert len(feed_resp.json()) >= len(drift_d.json())


async def test_drift_detail_endpoint(client, app) -> None:
    _test_app, _factory, ai_target_service = app
    token, org_id, _user_id = await _create_org_and_select(
        client, "driftdetail@example.com", "Drift Detail Org", "drift-detail-org",
    )
    target_id = await _register_target(ai_target_service, org_id)
    create_resp = await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_id, "cadence": "hourly"},
        headers=_auth_headers(token),
    )
    policy_id = create_resp.json()["id"]
    await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/activate",
        headers=_auth_headers(token),
    )
    await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/run-now",
        headers=_auth_headers(token),
    )
    _STATE["secure_headers"] = False
    await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/run-now",
        headers=_auth_headers(token),
    )
    drift_list = await client.get(
        f"/api/v1/continuous-validation/policies/{policy_id}/drift",
        headers=_auth_headers(token),
    )
    assert drift_list.json()
    drift_id = drift_list.json()[0]["id"]

    detail_resp = await client.get(
        f"/api/v1/continuous-validation/drift/{drift_id}", headers=_auth_headers(token),
    )
    assert detail_resp.status_code == 200, detail_resp.text
    assert detail_resp.json()["id"] == drift_id


async def test_drift_detail_unknown_id_returns_404(client, app) -> None:
    _test_app, _factory, _ai_target_service = app
    token, _org_id, _user_id = await _create_org_and_select(
        client, "driftunknown@example.com", "Drift Unknown Org", "drift-unknown-org",
    )
    resp = await client.get(
        "/api/v1/continuous-validation/drift/not-a-real-id", headers=_auth_headers(token),
    )
    assert resp.status_code == 404, resp.text


# ─── Cross-tenant isolation ─────────────────────────────────────────────────────


async def test_cross_tenant_policy_read_returns_404(client, app) -> None:
    _test_app, _factory, ai_target_service = app
    token_a, _org_a, _u1 = await _create_org_and_select(
        client, "tenanta@example.com", "Tenant A", "tenant-a-cv",
    )
    token_b, org_b, _u2 = await _create_org_and_select(
        client, "tenantb@example.com", "Tenant B", "tenant-b-cv",
    )
    target_b = await _register_target(ai_target_service, org_b)
    create_resp = await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_b, "cadence": "hourly"},
        headers=_auth_headers(token_b),
    )
    policy_id = create_resp.json()["id"]

    cross_read = await client.get(
        f"/api/v1/continuous-validation/policies/{policy_id}", headers=_auth_headers(token_a),
    )
    assert cross_read.status_code == 404, cross_read.text


async def test_cross_tenant_policy_list_stays_separate(client, app) -> None:
    _test_app, _factory, ai_target_service = app
    token_a, org_a, _u1 = await _create_org_and_select(
        client, "tenantlista@example.com", "Tenant List A", "tenant-list-a",
    )
    token_b, org_b, _u2 = await _create_org_and_select(
        client, "tenantlistb@example.com", "Tenant List B", "tenant-list-b",
    )
    target_a = await _register_target(ai_target_service, org_a)
    target_b = await _register_target(ai_target_service, org_b)
    await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_a, "cadence": "hourly"},
        headers=_auth_headers(token_a),
    )
    await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_b, "cadence": "hourly"},
        headers=_auth_headers(token_b),
    )

    list_a = await client.get(
        "/api/v1/continuous-validation/policies", headers=_auth_headers(token_a),
    )
    list_b = await client.get(
        "/api/v1/continuous-validation/policies", headers=_auth_headers(token_b),
    )
    ids_a = {p["id"] for p in list_a.json()}
    ids_b = {p["id"] for p in list_b.json()}
    assert ids_a.isdisjoint(ids_b)
    assert len(list_a.json()) == 1
    assert len(list_b.json()) == 1


async def test_cross_tenant_change_feed_stays_separate(client, app) -> None:
    _test_app, _factory, ai_target_service = app
    token_a, org_a, _u1 = await _create_org_and_select(
        client, "feeda@example.com", "Feed Org A", "feed-org-a",
    )
    token_b, _org_b, _u2 = await _create_org_and_select(
        client, "feedb@example.com", "Feed Org B", "feed-org-b",
    )
    target_a = await _register_target(ai_target_service, org_a)
    create_a = await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_a, "cadence": "hourly"},
        headers=_auth_headers(token_a),
    )
    policy_a = create_a.json()["id"]
    await client.post(
        f"/api/v1/continuous-validation/policies/{policy_a}/activate",
        headers=_auth_headers(token_a),
    )
    await client.post(
        f"/api/v1/continuous-validation/policies/{policy_a}/run-now",
        headers=_auth_headers(token_a),
    )
    _STATE["secure_headers"] = False
    await client.post(
        f"/api/v1/continuous-validation/policies/{policy_a}/run-now",
        headers=_auth_headers(token_a),
    )

    feed_b = await client.get(
        "/api/v1/continuous-validation/change-feed", headers=_auth_headers(token_b),
    )
    assert feed_b.status_code == 200, feed_b.text
    assert feed_b.json() == []


# ─── Permission enforcement ──────────────────────────────────────────────────────


async def test_viewer_role_cannot_create_policy(client, app) -> None:
    _test_app, factory, ai_target_service = app
    _owner_token, org_id, _u1 = await _create_org_and_select(
        client, "viewerowner@example.com", "Viewer Org", "viewer-org",
    )
    target_id = await _register_target(ai_target_service, org_id)
    viewer_token = await _add_member(
        factory, client, org_id, "viewer@example.com", MembershipRole.VIEWER,
    )

    resp = await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_id, "cadence": "hourly"},
        headers=_auth_headers(viewer_token),
    )
    assert resp.status_code == 403, resp.text


async def test_analyst_role_can_read_but_not_manage(client, app) -> None:
    _test_app, factory, ai_target_service = app
    owner_token, org_id, _u1 = await _create_org_and_select(
        client, "analystowner@example.com", "Analyst Org", "analyst-org",
    )
    target_id = await _register_target(ai_target_service, org_id)
    create_resp = await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_id, "cadence": "hourly"},
        headers=_auth_headers(owner_token),
    )
    policy_id = create_resp.json()["id"]
    analyst_token = await _add_member(
        factory, client, org_id, "analyst@example.com", MembershipRole.ANALYST,
    )

    read_resp = await client.get(
        f"/api/v1/continuous-validation/policies/{policy_id}", headers=_auth_headers(analyst_token),
    )
    assert read_resp.status_code == 200, read_resp.text

    manage_resp = await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/activate",
        headers=_auth_headers(analyst_token),
    )
    assert manage_resp.status_code == 403, manage_resp.text


async def test_viewer_role_cannot_run_now(client, app) -> None:
    _test_app, factory, ai_target_service = app
    owner_token, org_id, _u1 = await _create_org_and_select(
        client, "viewerrunnow@example.com", "Viewer Run Now Org", "viewer-run-now-org",
    )
    target_id = await _register_target(ai_target_service, org_id)
    create_resp = await client.post(
        "/api/v1/continuous-validation/policies",
        json={"target_id": target_id, "cadence": "hourly"},
        headers=_auth_headers(owner_token),
    )
    policy_id = create_resp.json()["id"]
    viewer_token = await _add_member(
        factory, client, org_id, "viewer2@example.com", MembershipRole.VIEWER,
    )

    run_resp = await client.post(
        f"/api/v1/continuous-validation/policies/{policy_id}/run-now",
        headers=_auth_headers(viewer_token),
    )
    assert run_resp.status_code == 403, run_resp.text


async def test_unauthenticated_request_rejected(client) -> None:
    resp = await client.get("/api/v1/continuous-validation/policies")
    assert resp.status_code in (401, 403)
