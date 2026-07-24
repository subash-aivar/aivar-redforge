"""Adversarial tests for M13 — Protocol-Aware Service Validation, at the
API/full-service level.

Mirrors tests/api/test_validation_executions_m12_isolation.py's fixture
pattern exactly — real router + real services + a real in-memory SQLite
schema, with a fake `_SequencedPolicyPort` for precise, deterministic
gate-sequencing control. Real owned local TCP fixtures only (SSH/MySQL/
PostgreSQL banner-shaped servers on ephemeral ports) — never an
external/unrelated internet target.

Covers: client cannot submit/select a validator, the second fresh-
policy-dispatch boundary blocks protocol-candidate steps exactly like
it blocks HTTP/TLS ones, hinted-vs-validated truth for a real protocol
candidate, and no secret/exception leakage through protocol evidence.
"""

from __future__ import annotations

import http.server
import socket
import struct
import threading
from dataclasses import dataclass, field
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_auth_service,
    get_effective_access_service,
    get_organization_service,
    get_token_service,
    get_user_status_service,
    get_validation_execution_service,
)
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.organizations import router as organizations_router
from redforge.api.v1.validation_executions import router as validation_executions_router
from redforge.application.ai_targets import AITargetService
from redforge.application.auth import AuthService
from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.organizations import OrganizationService
from redforge.application.security_conditions.service import TenantSecurityConditionService
from redforge.application.security_correlation.rules import (
    CorrelationRuleRegistry,
    MultipleSecurityConditionsOnAssetRule,
    PublicSensitiveServiceContextRule,
)
from redforge.application.security_correlation.service import TenantSecurityCorrelationService
from redforge.application.validation_execution import network_adapters
from redforge.application.validation_execution.adaptive_rules import default_adaptive_rule_registry
from redforge.application.validation_execution.execution_service import ValidationExecutionService
from redforge.application.validation_execution.protocol_validators import (
    default_protocol_validator_registry,
)
from redforge.domain.validation_execution.value_objects import AddressClass
from redforge.infrastructure.audit.logger import InMemoryAuditLog
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (
    AIAssetModel,
    AITargetModel,
    MembershipModel,
    OrganizationModel,
    SecurityConditionModel,
    SecurityCorrelationConditionModel,
    SecurityCorrelationEntityModel,
    SecurityCorrelationModel,
    UserModel,
    ValidationExecutionEventModel,
    ValidationExecutionModel,
    ValidationExecutionStepModel,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _allow_loopback_for_local_test_server(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        network_adapters, "ALLOWED_ADDRESS_CLASSES",
        frozenset({AddressClass.PUBLIC, AddressClass.LOOPBACK}),
    )


# ─── Owned local test servers ───────────────────────────────────────────────


_HTTP_PORT = 8080
_MYSQL_PORT = 3306  # already in DISCOVERY_PORT_POLICY_V1, unprivileged, bindable without root


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html>ok</html>")

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture(scope="module", autouse=True)
def _http_server():
    server = http.server.HTTPServer(("127.0.0.1", _HTTP_PORT), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def _mysql_greeting() -> bytes:
    """A real, well-formed MySQL initial-handshake greeting packet —
    protocol_version=10, a genuine server_version string, and the
    CLIENT_SSL capability bit set, matching exactly what a real MySQL
    8.x server sends before any authentication byte is exchanged."""
    payload = (
        bytes([0x0A])
        + b"8.0.35" + b"\x00"
        + b"\x01\x02\x03\x04"
        + b"AUTHDATA"
        + b"\x00"
        + struct.pack("<H", 0xFFFF)
    )
    header = struct.pack("<I", len(payload))[:3] + b"\x00"
    return header + payload


def _real_mysql_listener() -> tuple[socket.socket, threading.Event]:
    """A real, owned, loopback-only MySQL-handshake-shaped server.
    Port 3306 (unlike 22/ssh) needs no elevated privileges to bind,
    which is why this fixture — not an SSH one — exercises the "real
    protocol dispatch through the full discovery pipeline" tests below;
    SshBannerValidator's own real-banner behavior is already proven
    directly (bypassing the fixed discovery-port pipeline) in
    tests/unit/test_protocol_validators.py."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", _MYSQL_PORT))
    sock.listen(5)
    stop = threading.Event()

    def _accept_loop() -> None:
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                conn.sendall(_mysql_greeting())
            except OSError:
                pass
            finally:
                conn.close()

    thread = threading.Thread(target=_accept_loop, daemon=True)
    thread.start()
    return sock, stop


@pytest.fixture(scope="module", autouse=True)
def _mysql_server():
    sock, stop = _real_mysql_listener()
    yield
    stop.set()
    sock.close()


_HTTP_ENDPOINT = f"http://127.0.0.1:{_HTTP_PORT}/"


# ─── Fake policy port (legitimate seam, matches M11/M12's own test files) ────


@dataclass(frozen=True, slots=True)
class _Decision:
    decision: str
    decision_id: str
    reason_code: str


@dataclass
class _SequencedPolicyPort:
    queue: list[_Decision] = field(default_factory=list)
    calls: int = 0

    def push_allow(self) -> None:
        self.queue.append(_Decision("allow", f"dec-{self.calls + len(self.queue)}", "ok"))

    def push_deny(self, reason_code: str = "authorization_revoked") -> None:
        self.queue.append(_Decision("deny", f"dec-{self.calls + len(self.queue)}", reason_code))

    async def evaluate(self, *, organization_id, actor_user_id, action_class, entity_refs):
        self.calls += 1
        if self.queue:
            return self.queue.pop(0)
        return _Decision("allow", f"dec-auto-{self.calls}", "ok")


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
def policy() -> _SequencedPolicyPort:
    return _SequencedPolicyPort()


@pytest.fixture
async def app(policy: _SequencedPolicyPort):
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[
                AIAssetModel.__table__,
                AITargetModel.__table__,
                MembershipModel.__table__,
                OrganizationModel.__table__,
                SecurityConditionModel.__table__,
                SecurityCorrelationConditionModel.__table__,
                SecurityCorrelationEntityModel.__table__,
                SecurityCorrelationModel.__table__,
                UserModel.__table__,
                ValidationExecutionEventModel.__table__,
                ValidationExecutionModel.__table__,
                ValidationExecutionStepModel.__table__,
            ],
        )

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    events = InMemoryEventPublisher()
    hasher = Argon2PasswordHasher(time_cost=1, memory_cost=16384, parallelism=1)
    tokens = JWTTokenService(secret_key="test-secret-key-that-is-long-enough-32!", access_ttl=3600)

    org_service = OrganizationService(factory, events, InMemoryAuditLog())
    auth_service = AuthService(factory, hasher, tokens, events)
    ai_target_service = AITargetService(factory, events)
    tenant_asset_service = TenantAssetService(factory)
    security_condition_service = TenantSecurityConditionService(factory)

    correlation_registry = CorrelationRuleRegistry()
    correlation_registry.register(
        PublicSensitiveServiceContextRule(
            asset_service=tenant_asset_service, condition_service=security_condition_service,
        )
    )
    correlation_registry.register(
        MultipleSecurityConditionsOnAssetRule(condition_service=security_condition_service)
    )
    correlation_service = TenantSecurityCorrelationService(factory, correlation_registry)

    execution_service = ValidationExecutionService(
        factory, policy,
        ai_target_service, tenant_asset_service, security_condition_service,
        default_adaptive_rule_registry(), correlation_service,
        default_protocol_validator_registry(),
    )

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(organizations_router, prefix="/api/v1")
    test_app.include_router(validation_executions_router, prefix="/api/v1")

    test_app.dependency_overrides[get_organization_service] = lambda: org_service
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_effective_access_service] = lambda: _NoOpEffectiveAccessService()
    test_app.dependency_overrides[get_auth_service] = lambda: auth_service
    test_app.dependency_overrides[get_token_service] = lambda: tokens
    test_app.dependency_overrides[get_validation_execution_service] = lambda: execution_service

    yield test_app, factory, ai_target_service, tenant_asset_service, security_condition_service
    await engine.dispose()


@pytest.fixture
async def client(app):
    test_app, *_rest = app
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
    select_resp = await client.post(
        f"/api/v1/auth/organizations/{org_id}/select", headers=_auth_headers(unscoped),
    )
    assert select_resp.status_code == 200, select_resp.text
    scoped: str = select_resp.json()["access_token"]
    return scoped, org_id, user_id


async def _register_target(
    ai_target_service: AITargetService, organization_id: str, endpoint: str = _HTTP_ENDPOINT,
) -> str:
    dto = await ai_target_service.register(
        organization_id=organization_id, name="Owned Protocol Target", description="",
        target_type="ai_api", provider="custom", endpoint=endpoint,
    )
    return dto.id


async def _create_discovery_execution(
    client: AsyncClient, token: str, target_id: str, extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = {"target_id": target_id, "profile": "network_discovery_baseline_v1", **(extra or {})}
    resp = await client.post(
        "/api/v1/validation-executions", json=body, headers=_auth_headers(token),
    )
    assert resp.status_code == 201, resp.text
    result: dict[str, Any] = resp.json()
    return result


# ─── Tests ──────────────────────────────────────────────────────────────────


class TestClientCannotSelectOrInjectAValidator:
    async def test_client_supplied_validator_id_is_ignored_never_used(
        self, client: AsyncClient, app,
    ) -> None:
        _test_app, _factory, ai_target_service, *_ = app
        token, org, _ = await _create_org_and_select(client, "v1@test.com", "OrgA", "org-v1")
        target_id = await _register_target(ai_target_service, org)
        body = await _create_discovery_execution(
            client, token, target_id,
            extra={
                "validator_id": "ARBITRARY_EXPLOIT_VALIDATOR",
                "validators": [{"validator_id": "EVIL", "supported_protocol": "shell"}],
            },
        )
        # The request succeeds (extra fields are simply ignored by the
        # closed CreateExecutionRequest model) but no step anywhere in
        # the response was ever produced by a client-named validator —
        # every validator_id present is one of the four real,
        # server-registered ones or None.
        real_validator_ids = {
            "SSH_BANNER_V1", "MYSQL_HANDSHAKE_V1", "POSTGRESQL_PROTOCOL_V1", "REDIS_PING_V1",
        }
        for step in body["steps"]:
            assert step["validator_id"] is None or step["validator_id"] in real_validator_ids

    async def test_client_cannot_submit_a_raw_protocol_step_type(
        self, client: AsyncClient, app,
    ) -> None:
        _test_app, _factory, ai_target_service, *_ = app
        token, org, _ = await _create_org_and_select(client, "v2@test.com", "OrgA", "org-v2")
        target_id = await _register_target(ai_target_service, org)
        body = await _create_discovery_execution(
            client, token, target_id,
            extra={"steps": [{"step_type": "smb_enum", "target": "10.0.0.0/8"}]},
        )
        step_types = {s["step_type"] for s in body["steps"]}
        assert "smb_enum" not in step_types


class TestSecondPolicyBoundaryCoversProtocolSteps:
    async def test_revocation_before_protocol_dispatch_yields_zero_validator_calls(
        self, client: AsyncClient, app, policy: _SequencedPolicyPort,
    ) -> None:
        """The exact M12 pattern, proven again for an M13 protocol
        step: discovery fact observed -> authorization revoked ->
        adaptive rule matches -> the adaptive step's validator never
        actually dispatches (policy_denied, zero evidence, zero network
        I/O to the real MySQL fixture)."""
        _test_app, _factory, ai_target_service, *_ = app
        token, org, _ = await _create_org_and_select(client, "v3@test.com", "OrgA", "org-v3")
        target_id = await _register_target(
            ai_target_service, org, endpoint=f"http://127.0.0.1:{_MYSQL_PORT}/",
        )

        policy.push_allow()  # create-time
        policy.push_allow()  # pre-dispatch (initial plan)
        policy.push_deny("authorization_revoked")  # first adaptive dispatch check
        body = await _create_discovery_execution(client, token, target_id)

        adaptive = [s for s in body["steps"] if s["source"] == "adaptive"]
        assert adaptive, "a MYSQL_HANDSHAKE adaptive step should have been scheduled"
        mysql_steps = [s for s in adaptive if s["step_type"] == "mysql_handshake"]
        assert mysql_steps
        # The first adaptive step dispatched is denied at the fresh
        # policy check (policy_denied, zero evidence, zero validator
        # dispatch) — this milestone's own hard-stop-after-denial
        # semantics then SKIP every remaining pending step (including
        # any other genuinely-reachable protocol candidate, e.g. a real
        # local Postgres on 5432 in this dev environment) rather than
        # individually re-checking each one; either way, none of them
        # ever reach a validator.
        assert all(s["status"] in ("failed", "skipped") for s in adaptive)
        assert all(s["evidence"] == [] for s in adaptive)
        assert all(s["validator_id"] is None for s in adaptive)
        assert any(s["error_category"] == "policy_denied" for s in adaptive)


class TestHintedVsValidatedProtocolTruth:
    async def test_mysql_candidate_against_real_handshake_validates(
        self, client: AsyncClient, app,
    ) -> None:
        _test_app, _factory, ai_target_service, *_ = app
        token, org, _ = await _create_org_and_select(client, "v4@test.com", "OrgA", "org-v4")
        target_id = await _register_target(
            ai_target_service, org, endpoint=f"http://127.0.0.1:{_MYSQL_PORT}/",
        )
        body = await _create_discovery_execution(client, token, target_id)

        mysql_steps = [s for s in body["steps"] if s["step_type"] == "mysql_handshake"]
        assert mysql_steps, "Port3306MySqlRule should have scheduled a MYSQL_HANDSHAKE step"
        assert mysql_steps[0]["protocol_validation_state"] == "validated"
        assert mysql_steps[0]["validator_id"] == "MYSQL_HANDSHAKE_V1"
        version_values = {
            e["value"] for e in mysql_steps[0]["evidence"] if e["label"] == "server_version"
        }
        assert "8.0.35" in version_values

    async def test_no_evidence_ever_contains_a_traceback_or_exception_text(
        self, client: AsyncClient, app,
    ) -> None:
        """Across a full real discovery + protocol-validation run
        (including the genuinely-closed ports in DISCOVERY_PORT_POLICY_V1
        this fixture never opens — 22/443/3389/5432/6379/8443), every
        piece of persisted evidence must be a short, bounded, closed
        value — never a raw exception message or stack trace."""
        _test_app, _factory, ai_target_service, *_ = app
        token, org, _ = await _create_org_and_select(client, "v5@test.com", "OrgA", "org-v5")
        target_id = await _register_target(
            ai_target_service, org, endpoint=f"http://127.0.0.1:{_MYSQL_PORT}/",
        )
        body = await _create_discovery_execution(client, token, target_id)
        for step in body["steps"]:
            for item in step["evidence"]:
                assert "Traceback" not in item["value"]
                assert "line " not in item["value"]
                assert len(item["value"]) < 500
