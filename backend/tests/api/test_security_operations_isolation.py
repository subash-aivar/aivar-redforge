"""Adversarial isolation tests for the Security Operations Command
Center REST API (M15).

Exercises the full HTTP path with real routers, a real in-memory SQLite
schema, and the real ValidationExecutionService/ContinuousValidationPolicyService/
SecurityDriftService chain — matching test_continuous_validation_isolation.py's
established pattern. The M10 execution-policy gate uses the same
`_AlwaysAllowPolicyPort` test double that file uses.

`Permission.SECURITY_OPERATIONS_READ` is deliberately granted to every
tenant role (OWNER/ADMIN/SECURITY_MANAGER/ANALYST/MEMBER/VIEWER) —
mirroring VALIDATIONS_READ's own universal distribution — so there is
no role left to produce a genuine "authenticated but wrong permission"
403 for THIS specific permission; that adversarial dimension is instead
proven at the RBAC-table level (test_all_roles_have_security_operations_read)
and via the unauthenticated-401 tests below.
"""

from __future__ import annotations

import http.server
import json
import threading
from dataclasses import dataclass, field

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_auth_service,
    get_continuous_validation_policy_service,
    get_execution_telemetry_service,
    get_organization_service,
    get_runtime_operations_service,
    get_security_change_feed_service,
    get_security_operations_stream_service,
    get_security_operations_summary_service,
    get_token_service,
    get_user_status_service,
    get_validation_execution_service,
)
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.continuous_validation import router as continuous_validation_router
from redforge.api.v1.organizations import router as organizations_router
from redforge.api.v1.security_operations import router as security_operations_router
from redforge.application.ai_targets import AITargetService
from redforge.application.auth import AuthService
from redforge.application.continuous_validation.policy_service import (
    ContinuousValidationPolicyService,
)
from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.organizations import OrganizationService
from redforge.application.security_conditions.service import TenantSecurityConditionService
from redforge.application.security_correlation.rules import CorrelationRuleRegistry
from redforge.application.security_correlation.service import TenantSecurityCorrelationService
from redforge.application.security_operations.change_feed_service import (
    SecurityChangeFeedService,
)
from redforge.application.security_operations.execution_telemetry_service import (
    ExecutionTelemetryService,
)
from redforge.application.security_operations.runtime_operations_service import (
    RuntimeOperationsService,
)
from redforge.application.security_operations.stream_service import (
    SecurityOperationsStreamService,
)
from redforge.application.security_operations.summary_service import (
    SecurityOperationsSummaryService,
)
from redforge.application.validation_execution import network_adapters
from redforge.application.validation_execution.adaptive_rules import default_adaptive_rule_registry
from redforge.application.validation_execution.execution_service import ValidationExecutionService
from redforge.application.validation_execution.protocol_validators import (
    default_protocol_validator_registry,
)
from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole, Permission
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
    RuntimeComponentHealthStateModel,
    RuntimeComponentHealthTransitionModel,
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
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware

pytestmark = pytest.mark.asyncio


# ─── RBAC table-level check (no role left to produce a genuine 403) ───────────


async def test_all_tenant_roles_have_security_operations_read() -> None:
    for role in MembershipRole:
        assert Permission.SECURITY_OPERATIONS_READ in ROLE_PERMISSIONS[role], role


# ─── Owned local HTTP test server (in-process) ─────────────────────────────────

_PORT = 18399


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
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


@pytest.fixture(autouse=True)
def _allow_loopback_for_local_test_server(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        network_adapters, "ALLOWED_ADDRESS_CLASSES",
        frozenset({AddressClass.PUBLIC, AddressClass.LOOPBACK}),
    )


@pytest.fixture(autouse=True)
def _disable_visibility_lag_for_instant_isolation_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    """The commit-visibility safety margin (EVENT_VISIBILITY_LAG_SECONDS)
    deliberately delays surfacing a just-created event by a couple of
    seconds in production, to give a slower concurrent transaction time
    to land — see stream_service.py's own module docstring. These
    isolation tests create an event and read it back within the same
    request/response cycle (effectively instantly), so the lag is
    disabled here; the lag's actual safety property (never skipping an
    event under real concurrency) is proven separately by the dedicated
    PostgreSQL concurrency/ordering proof, which controls transaction
    timing explicitly rather than relying on wall-clock speed."""
    import redforge.application.security_operations.stream_service as stream_service_module

    monkeypatch.setattr(stream_service_module, "EVENT_VISIBILITY_LAG_SECONDS", 0.0)


@pytest.fixture(autouse=True)
def _fast_stream_intervals_for_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    """Production poll/heartbeat intervals (1s / 15s) would make an SSE
    test wait up to 15 real seconds for its first heartbeat frame —
    reduced here to keep tests fast; the intervals themselves carry no
    correctness property worth proving under real timing (unlike the
    visibility lag above)."""
    import redforge.api.v1.security_operations as security_operations_api_module

    monkeypatch.setattr(security_operations_api_module, "STREAM_POLL_INTERVAL_SECONDS", 0.05)
    monkeypatch.setattr(security_operations_api_module, "STREAM_HEARTBEAT_INTERVAL_SECONDS", 0.1)


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


class _NeverUnhealthyRuntime:
    async def aggregate_health(self):
        from redforge.application.platform.runtime_contracts import AggregatedHealth
        from redforge.shared.timestamps import utc_now

        return AggregatedHealth(overall_status="healthy", components=(), checked_at=utc_now())


async def _runtime_unhealthy_count() -> int:
    return 0


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

    telemetry_service = ExecutionTelemetryService(execution_service)
    stream_service = SecurityOperationsStreamService(factory)
    change_feed_service = SecurityChangeFeedService(factory)
    summary_service = SecurityOperationsSummaryService(
        factory, ai_target_service, tenant_asset_service, execution_service,
        condition_service, correlation_service, _runtime_unhealthy_count,
    )
    runtime_service = RuntimeOperationsService(_NeverUnhealthyRuntime())  # type: ignore[arg-type]

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(organizations_router, prefix="/api/v1")
    test_app.include_router(continuous_validation_router, prefix="/api/v1")
    test_app.include_router(security_operations_router, prefix="/api/v1")

    test_app.dependency_overrides[get_organization_service] = lambda: org_service
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_auth_service] = lambda: auth_service
    test_app.dependency_overrides[get_token_service] = lambda: tokens
    test_app.dependency_overrides[get_continuous_validation_policy_service] = (
        lambda: policy_service
    )
    test_app.dependency_overrides[get_validation_execution_service] = lambda: execution_service
    test_app.dependency_overrides[get_execution_telemetry_service] = lambda: telemetry_service
    test_app.dependency_overrides[get_security_operations_stream_service] = lambda: stream_service
    test_app.dependency_overrides[get_security_change_feed_service] = lambda: change_feed_service
    test_app.dependency_overrides[get_security_operations_summary_service] = lambda: summary_service
    test_app.dependency_overrides[get_runtime_operations_service] = lambda: runtime_service

    yield test_app, factory, ai_target_service, execution_service

    await engine.dispose()


@pytest.fixture
async def client(app):
    test_app, _factory, _ai, _exec = app
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


async def _register_target(
    ai_target_service: AITargetService, organization_id: str, endpoint: str = _TARGET_ENDPOINT,
) -> str:
    dto = await ai_target_service.register(
        organization_id=organization_id, name="Owned Test Target", description="",
        target_type="ai_api", provider="custom", endpoint=endpoint,
    )
    return str(dto.id)


async def _run_one_execution(execution_service, organization_id: str, user_id: str, target_id: str):
    return await execution_service.create_and_run(organization_id, target_id, user_id)


# ─── Unauthenticated access denied ──────────────────────────────────────────────


@pytest.mark.parametrize("path", [
    "/api/v1/security-operations/summary",
    "/api/v1/security-operations/changes",
    "/api/v1/security-operations/events",
    "/api/v1/security-operations/executions",
    "/api/v1/security-operations/runtime",
])
async def test_unauthenticated_get_denied(client: AsyncClient, path: str) -> None:
    resp = await client.get(path)
    assert resp.status_code == 401, resp.text


async def test_unauthenticated_stream_denied(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/security-operations/events/stream")
    assert resp.status_code == 401, resp.text


# ─── Cross-tenant isolation ─────────────────────────────────────────────────────


async def test_cross_tenant_execution_detail_returns_404(client: AsyncClient, app) -> None:
    _test_app, _factory, ai_target_service, execution_service = app
    token_a, _org_a, _user_a = await _create_org_and_select(
        client, "tenanta@example.com", "Tenant A", "tenant-a-so",
    )
    token_b, org_b, user_b = await _create_org_and_select(
        client, "tenantb@example.com", "Tenant B", "tenant-b-so",
    )
    target_b = await _register_target(ai_target_service, org_b)
    execution = await _run_one_execution(execution_service, org_b, user_b, target_b)

    cross_resp = await client.get(
        f"/api/v1/security-operations/executions/{execution.id}",
        headers=_auth_headers(token_a),
    )
    assert cross_resp.status_code == 404, cross_resp.text

    own_resp = await client.get(
        f"/api/v1/security-operations/executions/{execution.id}",
        headers=_auth_headers(token_b),
    )
    assert own_resp.status_code == 200, own_resp.text


async def test_cross_tenant_summary_stays_separate(client: AsyncClient, app) -> None:
    _test_app, _factory, ai_target_service, execution_service = app
    token_a, org_a, user_a = await _create_org_and_select(
        client, "tenanta2@example.com", "Tenant A2", "tenant-a2-so",
    )
    token_b, _org_b, _user_b = await _create_org_and_select(
        client, "tenantb2@example.com", "Tenant B2", "tenant-b2-so",
    )
    target_a = await _register_target(ai_target_service, org_a)
    await _run_one_execution(execution_service, org_a, user_a, target_a)

    resp_a = await client.get(
        "/api/v1/security-operations/summary", headers=_auth_headers(token_a),
    )
    resp_b = await client.get(
        "/api/v1/security-operations/summary", headers=_auth_headers(token_b),
    )
    assert resp_a.status_code == 200
    assert resp_b.status_code == 200
    assert resp_a.json()["active_targets"] == 1
    assert resp_b.json()["active_targets"] == 0


async def test_cross_tenant_stream_never_leaks(client: AsyncClient, app) -> None:
    _test_app, _factory, ai_target_service, execution_service = app
    token_a, org_a, user_a = await _create_org_and_select(
        client, "tenanta3@example.com", "Tenant A3", "tenant-a3-so",
    )
    token_b, _org_b, _user_b = await _create_org_and_select(
        client, "tenantb3@example.com", "Tenant B3", "tenant-b3-so",
    )
    target_a = await _register_target(ai_target_service, org_a)
    await _run_one_execution(execution_service, org_a, user_a, target_a)

    resp_b = await client.get(
        "/api/v1/security-operations/events", headers=_auth_headers(token_b),
    )
    assert resp_b.status_code == 200
    assert resp_b.json() == []

    resp_a = await client.get(
        "/api/v1/security-operations/events", headers=_auth_headers(token_a),
    )
    assert resp_a.status_code == 200
    assert len(resp_a.json()) > 0
    for event in resp_a.json():
        assert event["organization_id"] == org_a


# ─── Malformed input never 500s ─────────────────────────────────────────────────


async def test_malformed_execution_id_does_not_500(client: AsyncClient) -> None:
    token, _org_id, _user_id = await _create_org_and_select(
        client, "malformed1@example.com", "Malformed Org", "malformed-org-1",
    )
    resp = await client.get(
        "/api/v1/security-operations/executions/not-a-real-ulid",
        headers=_auth_headers(token),
    )
    assert resp.status_code == 404, resp.text


async def test_malformed_since_cursor_does_not_500(client: AsyncClient) -> None:
    token, _org_id, _user_id = await _create_org_and_select(
        client, "malformed2@example.com", "Malformed Org2", "malformed-org-2",
    )
    resp = await client.get(
        "/api/v1/security-operations/events",
        params={"since_cursor": "totally-not-a-cursor"},
        headers=_auth_headers(token),
    )
    assert resp.status_code == 200, resp.text


async def test_malformed_execution_state_filter_rejected_422(client: AsyncClient) -> None:
    token, _org_id, _user_id = await _create_org_and_select(
        client, "malformed3@example.com", "Malformed Org3", "malformed-org-3",
    )
    resp = await client.get(
        "/api/v1/security-operations/executions",
        params={"state": "not_a_real_state"},
        headers=_auth_headers(token),
    )
    assert resp.status_code == 422, resp.text


async def test_unknown_source_domain_filter_rejected_422(client: AsyncClient) -> None:
    token, _org_id, _user_id = await _create_org_and_select(
        client, "malformed4@example.com", "Malformed Org4", "malformed-org-4",
    )
    resp = await client.get(
        "/api/v1/security-operations/changes",
        params={"source_domain": "not_a_real_domain"},
        headers=_auth_headers(token),
    )
    assert resp.status_code == 422, resp.text


async def test_unsupported_period_rejected_422(client: AsyncClient) -> None:
    token, _org_id, _user_id = await _create_org_and_select(
        client, "malformed5@example.com", "Malformed Org5", "malformed-org-5",
    )
    resp = await client.get(
        "/api/v1/security-operations/summary",
        params={"period": "6h"},
        headers=_auth_headers(token),
    )
    assert resp.status_code == 422, resp.text


# ─── Resume / ordering / dedup ──────────────────────────────────────────────────


async def test_resume_starts_strictly_after_cursor_no_duplicate(
    client: AsyncClient, app,
) -> None:
    _test_app, _factory, ai_target_service, execution_service = app
    token, org_id, user_id = await _create_org_and_select(
        client, "resume1@example.com", "Resume Org", "resume-org-1",
    )
    target_id = await _register_target(ai_target_service, org_id)
    await _run_one_execution(execution_service, org_id, user_id, target_id)

    first = await client.get(
        "/api/v1/security-operations/events", headers=_auth_headers(token),
    )
    assert first.status_code == 200
    first_events = first.json()
    assert len(first_events) > 0
    last_cursor = first_events[-1]["cursor"]

    resumed = await client.get(
        "/api/v1/security-operations/events",
        params={"since_cursor": last_cursor},
        headers=_auth_headers(token),
    )
    assert resumed.status_code == 200
    resumed_events = resumed.json()
    seen_cursors = {e["cursor"] for e in first_events}
    for e in resumed_events:
        assert e["cursor"] not in seen_cursors


async def test_events_are_returned_in_deterministic_cursor_order(
    client: AsyncClient, app,
) -> None:
    _test_app, _factory, ai_target_service, execution_service = app
    token, org_id, user_id = await _create_org_and_select(
        client, "order1@example.com", "Order Org", "order-org-1",
    )
    target_id = await _register_target(ai_target_service, org_id)
    await _run_one_execution(execution_service, org_id, user_id, target_id)

    resp = await client.get(
        "/api/v1/security-operations/events", headers=_auth_headers(token),
    )
    cursors = [e["cursor"] for e in resp.json()]
    assert cursors == sorted(cursors)


# ─── No publish/mutation surface ────────────────────────────────────────────────


async def test_no_write_methods_registered_on_security_operations_router() -> None:
    """The brief requires this bounded context to be strictly read-only
    — no client-created events, no importance/source-domain override, no
    execution mutation under this namespace. Assert this structurally:
    every route this router registers is a GET."""
    for route in security_operations_router.routes:
        methods = getattr(route, "methods", set())
        assert methods <= {"GET", "HEAD"}, (route.path, methods)


# ─── Sentinel absence (no secrets/stack traces/SQL ever leak) ──────────────────


_FORBIDDEN_SENTINELS = (
    "Authorization", "Bearer ", "Set-Cookie", "password", "Traceback",
    "SELECT ", "INSERT INTO", "sqlalchemy", "asyncpg",
)


async def test_summary_and_changes_never_leak_sentinels(client: AsyncClient, app) -> None:
    _test_app, _factory, ai_target_service, execution_service = app
    token, org_id, user_id = await _create_org_and_select(
        client, "sentinel1@example.com", "Sentinel Org", "sentinel-org-1",
    )
    target_id = await _register_target(ai_target_service, org_id)
    await _run_one_execution(execution_service, org_id, user_id, target_id)

    for path in ("/api/v1/security-operations/summary", "/api/v1/security-operations/changes",
                 "/api/v1/security-operations/events", "/api/v1/security-operations/executions"):
        resp = await client.get(path, headers=_auth_headers(token))
        assert resp.status_code == 200
        raw = json.dumps(resp.json())
        for sentinel in _FORBIDDEN_SENTINELS:
            assert sentinel not in raw, (path, sentinel)


# ─── Execution telemetry is read-only and backend-derived ──────────────────────


async def test_execution_detail_phase_is_backend_enum_value(client: AsyncClient, app) -> None:
    _test_app, _factory, ai_target_service, execution_service = app
    token, org_id, user_id = await _create_org_and_select(
        client, "phase1@example.com", "Phase Org", "phase-org-1",
    )
    target_id = await _register_target(ai_target_service, org_id)
    execution = await _run_one_execution(execution_service, org_id, user_id, target_id)

    resp = await client.get(
        f"/api/v1/security-operations/executions/{execution.id}",
        headers=_auth_headers(token),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "%" not in body["summary"]["phase"]
    assert body["summary"]["phase"] in {
        "authorization", "resolution", "discovery", "service_validation",
        "adaptive_validation", "protocol_validation", "condition_processing",
        "correlation", "snapshot", "drift", "completed", "unknown",
    }
    for entry in body["timeline"]:
        assert "%" not in entry["phase"]


# ─── Runtime operations ─────────────────────────────────────────────────────────


async def test_runtime_components_returns_known_statuses_only(client: AsyncClient) -> None:
    token, _org_id, _user_id = await _create_org_and_select(
        client, "runtime1@example.com", "Runtime Org", "runtime-org-1",
    )
    resp = await client.get(
        "/api/v1/security-operations/runtime", headers=_auth_headers(token),
    )
    assert resp.status_code == 200
    for component in resp.json():
        assert component["status"] in {"healthy", "degraded", "unhealthy", "unknown"}


# ─── SSE stream ──────────────────────────────────────────────────────────────────
#
# httpx's ASGITransport does not support genuinely streaming/partial
# consumption of an unbounded StreamingResponse in this test harness —
# a probe confirmed `Request.is_disconnected()` never observes a client
# abort under ASGITransport (real ASGI servers like uvicorn detect real
# socket closure; ASGITransport has no socket to close), and the client
# side appears to wait for the full response before yielding any line,
# which hangs forever against an intentionally infinite stream. Rather
# than risk hanging the whole test session, the stream endpoint's
# cursor/ordering/tenant-isolation logic is proven via the equivalent
# `/events` polling endpoint above (same `SecurityOperationsStreamService
# .poll()` under the hood — the SSE handler is a thin framing wrapper
# around it, see `_sse_frame()`), and the real wire-level streaming
# behavior (genuine chunked transfer, heartbeat cadence, live
# disconnect/reconnect) is proven against a real running uvicorn server
# in the M15 live API acceptance script, where socket-level disconnect
# detection genuinely works.


async def test_sse_frame_formats_a_valid_frame_with_no_leaked_fields() -> None:
    from redforge.api.v1.security_operations import _sse_frame
    from redforge.domain.security_operations.operational_event import OperationalEvent
    from redforge.domain.security_operations.value_objects import (
        OperationalImportance,
        SourceDomain,
    )

    event = OperationalEvent(
        cursor="2026-01-01T00:00:00.000000|E|row-1", event_id="e1",
        organization_id="org-1", source_domain=SourceDomain.VALIDATION,
        importance=OperationalImportance.INFO, title="Validation started",
        summary="Validation started.", entity_type="validation_execution",
        entity_id="exec-1", occurred_at="2026-01-01T00:00:00+00:00",
    )
    frame = _sse_frame(event)
    assert frame.startswith("id: 2026-01-01T00:00:00.000000|E|row-1\n")
    assert "event: operational_event\n" in frame
    assert frame.endswith("\n\n")
    for sentinel in _FORBIDDEN_SENTINELS:
        assert sentinel not in frame


async def test_stream_endpoint_requires_permission_before_entering_generator(
    client: AsyncClient,
) -> None:
    """Confirms the SSE route is gated by the SAME require_permission
    dependency as every other route — an unauthenticated request never
    reaches the streaming generator at all (no hang risk, no partial
    response body ever produced) because FastAPI's dependency
    resolution runs and rejects the request before the endpoint
    function — and therefore the StreamingResponse — is ever
    constructed."""
    resp = await client.get("/api/v1/security-operations/events/stream")
    assert resp.status_code == 401
    assert resp.headers.get("content-type", "").startswith("text/event-stream") is False
