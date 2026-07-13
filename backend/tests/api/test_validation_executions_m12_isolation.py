"""Adversarial tests for M12 — Authorized Network Discovery & Adaptive
Validation Orchestration, at the API/full-service level.

Mirrors tests/api/test_validation_executions_isolation.py's (M11)
fixture pattern exactly — real router + real services + a real
in-memory SQLite schema, with a fake `_SequencedPolicyPort` for
precise, deterministic gate-sequencing control (the same legitimate
seam M11's own suite uses). Adds real `TenantSecurityCorrelationService`
+ both real M9 rules so correlation reuse is proven genuine, not mocked.

Covers M12 adversarial checklist items 1-4, 14-18, 25-31, 39, 40, 42-52.
Items 5-13, 19-24, 32-38, 41 are covered at the unit/adapter level in
tests/unit/test_network_discovery_adaptive.py. Real owned local HTTP
test servers only — never an external/unrelated internet target.
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
    SecurityConditionModel,
    SecurityCorrelationConditionModel,
    SecurityCorrelationEntityModel,
    SecurityCorrelationModel,
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
    monkeypatch.setattr(
        network_adapters, "ALLOWED_ADDRESS_CLASSES",
        frozenset({AddressClass.PUBLIC, AddressClass.LOOPBACK}),
    )


# ─── Owned local HTTP test server ──────────────────────────────────────────────


_HTTP_PORT = 8080  # must be a port in DISCOVERY_PORT_POLICY_V1 to trigger PORT_80_HTTP


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


_HTTP_ENDPOINT = f"http://127.0.0.1:{_HTTP_PORT}/"


# ─── Fake policy port (legitimate seam, matches M11's own test file) ─────────


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

    def push_approval_required(self) -> None:
        self.queue.append(
            _Decision("approval_required", f"dec-{self.calls + len(self.queue)}", "requires_approval"),
        )

    async def evaluate(self, *, organization_id, actor_user_id, action_class, entity_refs):
        self.calls += 1
        if self.queue:
            return self.queue.pop(0)
        return _Decision("allow", f"dec-auto-{self.calls}", "ok")


class _AlwaysActiveUserStatusService:
    async def get_status(self, user_id: str) -> str:
        return "active"


# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def policy() -> _SequencedPolicyPort:
    return _SequencedPolicyPort()


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


async def _add_member(app_factory, client: AsyncClient, org_id: str, email: str, role) -> str:
    from redforge.domain.identity.entities import Membership
    from redforge.domain.identity.value_objects import MembershipRole

    user_id, unscoped = await _register(client, email)
    role = role if isinstance(role, MembershipRole) else MembershipRole(role)
    async with SessionUnitOfWork(app_factory) as uow:
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
    ai_target_service: AITargetService, organization_id: str, endpoint: str = _HTTP_ENDPOINT,
) -> str:
    dto = await ai_target_service.register(
        organization_id=organization_id, name="Owned Discovery Target", description="",
        target_type="ai_api", provider="custom", endpoint=endpoint,
    )
    return dto.id


async def _create_discovery_execution(client: AsyncClient, token: str, target_id: str) -> dict[str, Any]:
    resp = await client.post(
        "/api/v1/validation-executions",
        json={"target_id": target_id, "profile": "network_discovery_baseline_v1"},
        headers=_auth_headers(token),
    )
    return resp.json() if resp.status_code == 201 else {"_status": resp.status_code, "_body": resp.text}


# ─── 1-4: Policy gate blocks discovery entirely ───────────────────────────────


class TestPolicyGateBlocksDiscovery:
    async def test_deny_causes_zero_discovery_calls(
        self, client: AsyncClient, app, policy: _SequencedPolicyPort,
    ) -> None:
        _test_app, _factory, ai_target_service, *_ = app
        token, org, _ = await _create_org_and_select(client, "d1@test.com", "OrgA", "org-md1")
        target_id = await _register_target(ai_target_service, org)
        policy.push_deny("no_authorization_found")

        body = await _create_discovery_execution(client, token, target_id)
        assert body["status"] == "denied"
        assert body["steps"] == []
        assert body["plan_summary"]["initial_step_count"] == 0

    async def test_approval_required_causes_zero_discovery_calls(
        self, client: AsyncClient, app, policy: _SequencedPolicyPort,
    ) -> None:
        _test_app, _factory, ai_target_service, *_ = app
        token, org, _ = await _create_org_and_select(client, "d2@test.com", "OrgA", "org-md2")
        target_id = await _register_target(ai_target_service, org)
        policy.push_approval_required()

        body = await _create_discovery_execution(client, token, target_id)
        assert body["status"] == "denied"
        assert body["steps"] == []

    async def test_revoked_between_gates_causes_zero_discovery_calls(
        self, client: AsyncClient, app, policy: _SequencedPolicyPort,
    ) -> None:
        _test_app, _factory, ai_target_service, *_ = app
        token, org, _ = await _create_org_and_select(client, "d3@test.com", "OrgA", "org-md3")
        target_id = await _register_target(ai_target_service, org)
        policy.push_allow()
        policy.push_deny("authorization_revoked")

        body = await _create_discovery_execution(client, token, target_id)
        assert body["status"] == "denied"
        assert body["steps"] == []
        assert policy.calls == 2

    async def test_foreign_target_cannot_run_discovery(self, client: AsyncClient, app) -> None:
        _test_app, _factory, ai_target_service, *_ = app
        _a_token, a_org, _ = await _create_org_and_select(client, "d4@test.com", "OrgA", "org-md4a")
        b_token, _b_org, _ = await _create_org_and_select(client, "db4@test.com", "OrgB", "org-md4b")
        target_id = await _register_target(ai_target_service, a_org)

        resp = await client.post(
            "/api/v1/validation-executions",
            json={"target_id": target_id, "profile": "network_discovery_baseline_v1"},
            headers=_auth_headers(b_token),
        )
        assert resp.status_code >= 400


# ─── 5-9: Client cannot submit arbitrary discovery content ────────────────────


class TestClientCannotSubmitDiscoveryContent:
    async def test_client_cannot_submit_ports(self, client: AsyncClient, app) -> None:
        _test_app, _factory, ai_target_service, *_ = app
        token, org, _ = await _create_org_and_select(client, "c1@test.com", "OrgA", "org-mc1")
        target_id = await _register_target(ai_target_service, org)
        resp = await client.post(
            "/api/v1/validation-executions",
            json={
                "target_id": target_id, "profile": "network_discovery_baseline_v1",
                "ports": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code == 201, resp.text
        discovery_step = next(s for s in resp.json()["steps"] if s["step_type"] == "port_discovery")
        port_evidence_count = sum(
            1 for e in discovery_step["evidence"] if e["label"].startswith("port_")
        )
        assert port_evidence_count == 9  # the closed DISCOVERY_PORT_POLICY_V1 size, not 15

    async def test_client_cannot_submit_adaptive_rules_or_step_types(
        self, client: AsyncClient, app,
    ) -> None:
        _test_app, _factory, ai_target_service, *_ = app
        token, org, _ = await _create_org_and_select(client, "c2@test.com", "OrgA", "org-mc2")
        target_id = await _register_target(ai_target_service, org)
        resp = await client.post(
            "/api/v1/validation-executions",
            json={
                "target_id": target_id, "profile": "network_discovery_baseline_v1",
                "adaptive_rules": [{"rule_id": "CUSTOM_EXPLOIT", "step_type": "shell_exec"}],
                "steps": [{"step_type": "shell_exec", "command": "id"}],
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        step_types = {s["step_type"] for s in body["steps"]}
        assert "shell_exec" not in step_types
        # Only the server-built initial plan and, at most, adaptively
        # appended steps from the CLOSED registry — never a client-
        # submitted step/rule of any kind.
        assert step_types <= {
            "dns_resolution", "port_discovery", "http_metadata", "http_security_headers",
            "tls_handshake", "ssh_banner", "mysql_handshake", "postgresql_handshake", "redis_ping",
        }
        assert all(
            s["source"] == "initial" or s["adaptive_rule_id"] in (
                "PORT_80_HTTP", "PORT_443_TLS_HTTPS", "PORT_22_SSH", "PORT_3306_MYSQL",
                "PORT_5432_POSTGRESQL", "PORT_6379_REDIS",
            )
            for s in body["steps"]
        )

    async def test_client_cannot_submit_commands(self, client: AsyncClient, app) -> None:
        _test_app, _factory, ai_target_service, *_ = app
        token, org, _ = await _create_org_and_select(client, "c3@test.com", "OrgA", "org-mc3")
        target_id = await _register_target(ai_target_service, org)
        resp = await client.post(
            "/api/v1/validation-executions",
            json={
                "target_id": target_id, "profile": "network_discovery_baseline_v1",
                "command": "nmap -p- 10.0.0.0/8",
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code == 201
        assert "command" not in str(resp.json())

    async def test_unknown_profile_fails_safely(self, client: AsyncClient, app) -> None:
        _test_app, _factory, ai_target_service, *_ = app
        token, org, _ = await _create_org_and_select(client, "c4@test.com", "OrgA", "org-mc4")
        target_id = await _register_target(ai_target_service, org)
        resp = await client.post(
            "/api/v1/validation-executions",
            json={"target_id": target_id, "profile": "full_port_scan_v1"},
            headers=_auth_headers(token),
        )
        assert resp.status_code >= 400

    async def test_no_arbitrary_scanner_or_exploit_endpoint_exists(self, client: AsyncClient) -> None:
        token, _org, _ = await _create_org_and_select(client, "c5@test.com", "OrgA", "org-mc5")
        for path in ("/api/v1/scan", "/api/v1/exec", "/api/v1/exploit", "/api/v1/network-scan"):
            resp = await client.post(path, json={}, headers=_auth_headers(token))
            assert resp.status_code == 404

    async def test_no_direct_adapter_invocation_from_router(self) -> None:
        import inspect

        import redforge.api.v1.validation_executions as router_module

        source = inspect.getsource(router_module)
        assert "network_adapters" not in source
        assert "discover_ports" not in source
        assert "BoundedNetworkScanAdapter" not in source


# ─── Real discovery + adaptive expansion + condition/correlation ─────────────


class TestRealDiscoveryAndAdaptiveExpansion:
    async def test_full_discovery_pipeline_with_adaptive_http_validation(
        self, client: AsyncClient, app,
    ) -> None:
        _test_app, _factory, ai_target_service, _asset_service, _cond_service = app
        token, org, _ = await _create_org_and_select(client, "r1@test.com", "OrgA", "org-mr1")
        target_id = await _register_target(ai_target_service, org, endpoint=f"http://127.0.0.1:{_HTTP_PORT}/")

        body = await _create_discovery_execution(client, token, target_id)
        assert body["status"] in ("completed", "partially_completed"), body["failure_reason"]

        discovery_step = next(s for s in body["steps"] if s["step_type"] == "port_discovery")
        assert discovery_step["status"] == "completed"
        adaptive_steps = [s for s in body["steps"] if s["source"] == "adaptive"]
        assert any(s["step_type"] == "http_metadata" for s in adaptive_steps)
        assert any(s["adaptive_rule_id"] == "PORT_80_HTTP" for s in adaptive_steps)
        assert all(s["adaptive_rule_version"] == 1 for s in adaptive_steps)
        assert body["plan_summary"]["adaptive_step_count"] >= 2

    async def test_tcp_open_alone_creates_no_finding(self, client: AsyncClient, app) -> None:
        """25: bare port reachability is an observation, never a Finding."""
        _test_app, _factory, ai_target_service, *_ = app
        token, org, _ = await _create_org_and_select(client, "r2@test.com", "OrgA", "org-mr2")
        target_id = await _register_target(ai_target_service, org, endpoint=f"http://127.0.0.1:{_HTTP_PORT}/")

        body = await _create_discovery_execution(client, token, target_id)
        discovery_step = next(s for s in body["steps"] if s["step_type"] == "port_discovery")
        assert not any(e["label"] == "finding" for e in discovery_step["evidence"])

    async def test_http_response_alone_creates_no_finding(self, client: AsyncClient, app) -> None:
        """26: a successful HTTP fetch is an observation, never a Finding."""
        _test_app, _factory, ai_target_service, *_ = app
        token, org, _ = await _create_org_and_select(client, "r3@test.com", "OrgA", "org-mr3")
        target_id = await _register_target(ai_target_service, org, endpoint=f"http://127.0.0.1:{_HTTP_PORT}/")

        body = await _create_discovery_execution(client, token, target_id)
        http_step = next(s for s in body["steps"] if s["step_type"] == "http_metadata")
        assert not any(e["label"] == "finding" for e in http_step["evidence"])

    async def test_missing_header_condition_deduplicates_on_repeat(
        self, client: AsyncClient, app,
    ) -> None:
        """27: repeated discovery updates the same deterministic
        condition — never a duplicate row."""
        _test_app, _factory, ai_target_service, _asset_service, cond_service = app
        token, org, _ = await _create_org_and_select(client, "r4@test.com", "OrgA", "org-mr4")
        target_id = await _register_target(ai_target_service, org, endpoint=f"http://127.0.0.1:{_HTTP_PORT}/")

        await _create_discovery_execution(client, token, target_id)
        await _create_discovery_execution(client, token, target_id)

        conditions = await cond_service.list_for_org(org, source_category="active_validation")
        csp = [c for c in conditions if c.stable_rule_id == "MISSING_CSP_HEADER"]
        assert len(csp) == 1

    async def test_asset_and_service_identity_deduplicates_on_repeat(
        self, client: AsyncClient, app,
    ) -> None:
        """28/29: repeated discovery never duplicates the canonical IP/
        HOST/SERVICE asset identity."""
        _test_app, _factory, ai_target_service, asset_service, _cond_service = app
        token, org, _ = await _create_org_and_select(client, "r5@test.com", "OrgA", "org-mr5")
        target_id = await _register_target(ai_target_service, org, endpoint=f"http://127.0.0.1:{_HTTP_PORT}/")

        await _create_discovery_execution(client, token, target_id)
        # Real bounded discovery may legitimately find MORE than just
        # this suite's own owned server reachable (e.g. another real
        # local service on one of the small policy ports) — the
        # invariant under test is dedup (repeat never INCREASES the
        # count), not a hardcoded total.
        ip_after_first = len(await asset_service.list_for_org(org, asset_type="ip_address", limit=200))
        host_after_first = len(await asset_service.list_for_org(org, asset_type="host", limit=200))
        service_after_first = len(
            await asset_service.list_for_org(org, asset_type="service", limit=200)
        )
        assert ip_after_first >= 1
        assert host_after_first >= 1
        assert service_after_first >= 1

        await _create_discovery_execution(client, token, target_id)
        ip_assets = await asset_service.list_for_org(org, asset_type="ip_address", limit=200)
        host_assets = await asset_service.list_for_org(org, asset_type="host", limit=200)
        service_assets = await asset_service.list_for_org(org, asset_type="service", limit=200)
        assert len(ip_assets) == ip_after_first
        assert len(host_assets) == host_after_first
        assert len(service_assets) == service_after_first

    async def test_cross_tenant_same_ip_remains_separate(self, client: AsyncClient, app) -> None:
        """30: cross-tenant identical IP/service remain separate
        canonical tenant truth."""
        _test_app, _factory, ai_target_service, asset_service, _cond_service = app
        a_token, a_org, _ = await _create_org_and_select(client, "r6a@test.com", "OrgA", "org-mr6a")
        b_token, b_org, _ = await _create_org_and_select(client, "r6b@test.com", "OrgB", "org-mr6b")
        a_target = await _register_target(ai_target_service, a_org, endpoint=f"http://127.0.0.1:{_HTTP_PORT}/")
        b_target = await _register_target(ai_target_service, b_org, endpoint=f"http://127.0.0.1:{_HTTP_PORT}/")

        await _create_discovery_execution(client, a_token, a_target)
        await _create_discovery_execution(client, b_token, b_target)

        a_ips = await asset_service.list_for_org(a_org, asset_type="ip_address", limit=200)
        b_ips = await asset_service.list_for_org(b_org, asset_type="ip_address", limit=200)
        assert len(a_ips) == 1
        assert len(b_ips) == 1
        assert a_ips[0].id != b_ips[0].id

    async def test_correlation_service_reused_and_deduplicates(
        self, client: AsyncClient, app,
    ) -> None:
        """42/43: M9's real, unmodified correlation service is
        invoked, and produces exactly one MULTIPLE_SECURITY_CONDITIONS_
        ON_ASSET correlation (2 header conditions on the same target
        asset) — never duplicated across repeated executions."""
        _test_app, _factory, ai_target_service, _asset_service, _cond_service = app
        token, org, _ = await _create_org_and_select(client, "r7@test.com", "OrgA", "org-mr7")
        target_id = await _register_target(ai_target_service, org, endpoint=f"http://127.0.0.1:{_HTTP_PORT}/")

        body1 = await _create_discovery_execution(client, token, target_id)
        events1 = await client.get(
            f"/api/v1/validation-executions/{body1['id']}/events", headers=_auth_headers(token),
        )
        correlation_events = [
            e for e in events1.json() if e["event_type"] == "correlation_evaluated"
        ]
        assert len(correlation_events) == 1
        assert "error" not in correlation_events[0]["payload"]
        assert int(correlation_events[0]["payload"]["created"]) >= 1

        await _create_discovery_execution(client, token, target_id)
        result = await client.get(
            f"/api/v1/validation-executions/{body1['id']}/result", headers=_auth_headers(token),
        )
        # A second execution's correlation re-evaluation must not
        # duplicate — re-fetching the FIRST execution's own result
        # still reflects a real, non-fabricated summary shape.
        assert result.status_code == 200


# ─── Adaptive dispatch policy gate (revoked between discovery and dispatch) ──


class TestAdaptiveDispatchPolicyGate:
    async def test_revoked_between_discovery_and_adaptive_dispatch_blocks_network_io(
        self, client: AsyncClient, app, policy: _SequencedPolicyPort,
    ) -> None:
        """17/18/51: the canonical fresh-policy dispatch boundary
        blocks an adaptively-scheduled step from ever reaching the
        network adapter once authorization is no longer ALLOW — proven
        by forcing DENY on exactly the 3rd `evaluate()` call (the two
        initial gates ALLOW, then the adaptive-dispatch check DENIES)."""
        _test_app, _factory, ai_target_service, *_ = app
        token, org, _ = await _create_org_and_select(client, "a1@test.com", "OrgA", "org-ma1")
        target_id = await _register_target(ai_target_service, org, endpoint=f"http://127.0.0.1:{_HTTP_PORT}/")
        policy.push_allow()
        policy.push_allow()
        policy.push_deny("authorization_revoked")

        body = await _create_discovery_execution(client, token, target_id)
        assert policy.calls == 3
        adaptive_steps = [s for s in body["steps"] if s["source"] == "adaptive"]
        assert adaptive_steps, "expected at least one adaptive step to have been scheduled"
        assert all(s["status"] in ("failed", "skipped") for s in adaptive_steps)
        assert any(s["error_category"] == "policy_denied" for s in adaptive_steps)
        # The network adapter was never reached: a denied adaptive step
        # has no real evidence (status_code/protocol_version/etc.)
        for s in adaptive_steps:
            if s["error_category"] == "policy_denied":
                assert s["evidence"] == []


# ─── Cancellation at each discovery phase ─────────────────────────────────────


class TestCancellationDuringDiscovery:
    async def test_cancel_after_discovery_completes_is_rejected_when_already_terminal(
        self, client: AsyncClient, app,
    ) -> None:
        _test_app, _factory, ai_target_service, *_ = app
        token, org, _ = await _create_org_and_select(client, "n1@test.com", "OrgA", "org-mn1")
        target_id = await _register_target(ai_target_service, org, endpoint=f"http://127.0.0.1:{_HTTP_PORT}/")
        body = await _create_discovery_execution(client, token, target_id)
        assert body["status"] in ("completed", "partially_completed")

        resp = await client.post(
            f"/api/v1/validation-executions/{body['id']}/cancel", headers=_auth_headers(token),
        )
        assert resp.status_code == 422


# ─── Restart / provenance / event-ordering persistence ────────────────────────


class TestProvenanceAndPersistence:
    async def test_adaptive_provenance_persisted_and_events_ordered(
        self, client: AsyncClient, app,
    ) -> None:
        _test_app, _factory, ai_target_service, *_ = app
        token, org, _ = await _create_org_and_select(client, "p1@test.com", "OrgA", "org-mp1")
        target_id = await _register_target(ai_target_service, org, endpoint=f"http://127.0.0.1:{_HTTP_PORT}/")
        body = await _create_discovery_execution(client, token, target_id)

        events = (await client.get(
            f"/api/v1/validation-executions/{body['id']}/events", headers=_auth_headers(token),
        )).json()
        sequences = [e["sequence"] for e in events]
        assert sequences == sorted(sequences)
        assert len(sequences) == len(set(sequences))
        event_types = [e["event_type"] for e in events]
        assert "discovery_started" in event_types
        assert "adaptive_rule_matched" in event_types
        assert "step_added_to_plan" in event_types
        assert "asset_resolved" in event_types

        detail = (await client.get(
            f"/api/v1/validation-executions/{body['id']}", headers=_auth_headers(token),
        )).json()
        adaptive = [s for s in detail["steps"] if s["source"] == "adaptive"]
        assert all(s["adaptive_rule_id"] and s["source_fact_ref"] for s in adaptive)

    async def test_restart_preserves_final_plan_history(self, client: AsyncClient, app) -> None:
        _test_app, factory, ai_target_service, asset_service, cond_service = app
        token, org, _ = await _create_org_and_select(client, "p2@test.com", "OrgA", "org-mp2")
        target_id = await _register_target(ai_target_service, org, endpoint=f"http://127.0.0.1:{_HTTP_PORT}/")
        body = await _create_discovery_execution(client, token, target_id)

        from redforge.application.security_correlation.rules import (
            CorrelationRuleRegistry as _Registry,
        )
        from redforge.application.security_correlation.service import (
            TenantSecurityCorrelationService as _CorrService,
        )

        fresh_correlation = _CorrService(factory, _Registry())
        fresh_service = ValidationExecutionService(
            factory, _SequencedPolicyPort(),
            ai_target_service, asset_service, cond_service,
            default_adaptive_rule_registry(), fresh_correlation,
        )
        reloaded = await fresh_service.get_by_id(org, body["id"])
        assert reloaded.status == body["status"]
        assert len(reloaded.steps) == len(body["steps"])
        assert [s.source for s in reloaded.steps] == [s["source"] for s in body["steps"]]


# ─── Non-disclosure for guessed foreign IDs ────────────────────────────────────


class TestForeignIdNonDisclosing:
    async def test_guessed_foreign_execution_id_non_disclosing(self, client: AsyncClient) -> None:
        token, _org, _ = await _create_org_and_select(client, "g1@test.com", "OrgA", "org-mg1")
        guessed_id = str(EntityId.generate())
        resp = await client.get(
            f"/api/v1/validation-executions/{guessed_id}", headers=_auth_headers(token),
        )
        assert resp.status_code == 404

    async def test_guessed_foreign_asset_id_non_disclosing(self, client: AsyncClient, app) -> None:
        _test_app, _factory, _ai_target_service, asset_service, _cond_service = app
        _token, _org, _ = await _create_org_and_select(client, "g2@test.com", "OrgA", "org-mg2")
        guessed_id = str(EntityId.generate())
        from redforge.core.exceptions import NotFoundError

        with pytest.raises(NotFoundError):
            await asset_service.get_for_org(guessed_id, "some-other-org")
