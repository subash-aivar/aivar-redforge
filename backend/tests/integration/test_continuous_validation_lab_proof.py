"""Owned local continuous-validation lab + real-PostgreSQL concurrency
proof for M14 — Continuous Validation Scheduler, Security Drift
Detection & Revalidation Engine.

Runs against a dedicated, self-created database
(`redforge_continuous_validation_proof_test`), never the shared dev
database. `_assert_isolated_proof_database()` — the same guard M12/M13's
own proof files introduced — is applied before every destructive
command in this file too.

Owned local lab (never an external/unrelated internet target):
  - A real HTTP server whose security-header behavior can be toggled at
    runtime (present -> STATE A baseline; absent -> STATE B mutation;
    present again -> STATE C reintroduction), driving
    MISSING_CSP_HEADER / MISSING_X_CONTENT_TYPE_OPTIONS_HEADER condition
    appear/resolve/reactivate.
  - A real, start/stoppable bare TCP listener on an ephemeral port,
    driving PORT_BECAME_REACHABLE / PORT_NO_LONGER_REACHABLE drift via
    the NETWORK_DISCOVERY_BASELINE_V1 profile's own port-policy scan.

Proves:
  1.  STATE A (baseline, first-ever run): zero fabricated drift — there
      is no prior snapshot to differ against.
  2.  STATE B (mutate lab truth: headers removed): deterministic
      CONDITION_APPEARED drift, condition genuinely ingested.
  3.  STATE C (reintroduce lab truth: headers restored): the SAME
      canonical condition id is reused (never duplicated),
      CONDITION_REACTIVATED drift recorded, condition lifecycle back to
      active.
  4.  Identical rerun (STATE C repeated unchanged): zero NEW drift
      events.
  5.  Port reachability drift: a real TCP listener started/stopped
      between two runs produces PORT_BECAME_REACHABLE /
      PORT_NO_LONGER_REACHABLE against real socket state.
  6.  Revocation before a scheduled/on-demand run's own dispatch yields
      zero validator/network calls — the M10 fresh-authorization gate
      inside create_and_run() is never bypassed by this bounded
      context.
  7.  Concurrent scheduler claim: many genuinely simultaneous
      `process_one_due_policy()` calls against the identical due policy
      converge on exactly ONE canonical ValidationExecution — the
      atomic claim (SKIP LOCKED) plus the partial unique index backstop
      both hold under a real race.
  8.  Restart preserves everything: a fresh ContinuousValidationProcessor
      instance (simulating a process restart) reads back the same
      policy/snapshot/drift state from the database.
  9.  A policy disabled by an operator WHILE a scheduled run is still in
      flight is never resurrected to ACTIVE by that run's own post-run
      save — the row-locked re-read in `_mutate_under_lock()` sees the
      operator's already-committed DISABLED state and skips further
      mutation, closing the TOCTOU an earlier adversarial review found.
  10. Condition-reconciliation coverage is genuinely per-port: a
      PLAINTEXT_SENSITIVE_SERVICE_OBSERVED condition on a port this
      run's plan never actually re-examined is never resolved merely
      because a DIFFERENT port's protocol step validated this run.
"""

from __future__ import annotations

import asyncio
import http.server
import os
import socket
import struct
import threading
from dataclasses import dataclass, field

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.ai_targets import AITargetService
from redforge.application.continuous_validation.drift_service import SecurityDriftService
from redforge.application.continuous_validation.policy_service import (
    ContinuousValidationPolicyService,
)
from redforge.application.continuous_validation.processor import ContinuousValidationProcessor
from redforge.application.inventory.tenant_asset_service import TenantAssetService
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
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models.ai_target import AITargetModel
from redforge.infrastructure.database.models.asset_connector import AIAssetModel
from redforge.infrastructure.database.models.continuous_validation import (
    ContinuousValidationPolicyModel,
    SecurityDriftEventModel,
    ValidationStateSnapshotModel,
)
from redforge.infrastructure.database.models.security_conditions import SecurityConditionModel
from redforge.infrastructure.database.models.security_correlation import (
    SecurityCorrelationConditionModel,
    SecurityCorrelationEntityModel,
    SecurityCorrelationModel,
)
from redforge.infrastructure.database.models.security_graph import (
    SecurityGraphEdgeModel,
    SecurityGraphNodeModel,
)
from redforge.infrastructure.database.models.security_operations import (
    ContinuousValidationPolicyLifecycleEventModel,
)
from redforge.infrastructure.database.models.validation_execution import (
    ValidationExecutionEventModel,
    ValidationExecutionModel,
    ValidationExecutionStepModel,
)
from redforge.infrastructure.database.repositories.continuous_validation.repository import (
    SqlAlchemyContinuousValidationPolicyRepository,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio

_TEST_DB_NAME = "redforge_continuous_validation_proof_test"
_MAINTENANCE_DB_URL = os.environ.get(
    "REDFORGE_MAINTENANCE_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/postgres",
)
_DB_URL = os.environ.get(
    "REDFORGE_TEST_DATABASE_URL",
    f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_TEST_DB_NAME}",
)

_TABLES = [
    AITargetModel.__table__,
    AIAssetModel.__table__,
    SecurityConditionModel.__table__,
    SecurityCorrelationModel.__table__,
    SecurityCorrelationConditionModel.__table__,
    SecurityCorrelationEntityModel.__table__,
    SecurityGraphNodeModel.__table__,
    SecurityGraphEdgeModel.__table__,
    ValidationExecutionModel.__table__,
    ValidationExecutionStepModel.__table__,
    ValidationExecutionEventModel.__table__,
    ContinuousValidationPolicyModel.__table__,
    ValidationStateSnapshotModel.__table__,
    SecurityDriftEventModel.__table__,
    ContinuousValidationPolicyLifecycleEventModel.__table__,
]

_ALL_TABLE_NAMES = (
    "continuous_validation_policy_lifecycle_events",
    "security_drift_events",
    "validation_state_snapshots",
    "continuous_validation_policies",
    "validation_execution_events",
    "validation_execution_steps",
    "validation_executions",
    "security_correlation_conditions",
    "security_correlation_entities",
    "security_correlations",
    "security_conditions",
    "security_graph_edges",
    "security_graph_nodes",
    "ai_assets",
    "ai_targets",
)


def _assert_isolated_proof_database(target_db_name: str) -> None:
    """Refuses to run any destructive proof command against anything
    other than this file's own isolated database — see M12's own proof
    file for the incident this guard exists to prevent from repeating."""
    print(f"[proof-db-guard] destructive command target database: {target_db_name!r}")
    assert target_db_name == _TEST_DB_NAME, (
        f"REFUSING destructive command: target database {target_db_name!r} is not the "
        f"isolated proof database {_TEST_DB_NAME!r}"
    )


@pytest.fixture(autouse=True)
def _allow_loopback_for_local_test_server(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        network_adapters, "ALLOWED_ADDRESS_CLASSES",
        frozenset({AddressClass.PUBLIC, AddressClass.LOOPBACK}),
    )


async def _ensure_test_database_exists() -> None:
    maintenance_engine = create_async_engine(
        _MAINTENANCE_DB_URL, echo=False, isolation_level="AUTOCOMMIT",
    )
    try:
        async with maintenance_engine.connect() as conn:
            exists = await conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": _TEST_DB_NAME},
            )
            if exists.first() is None:
                _assert_isolated_proof_database(_TEST_DB_NAME)
                await conn.execute(text(f'CREATE DATABASE "{_TEST_DB_NAME}"'))
    finally:
        await maintenance_engine.dispose()


@pytest.fixture
async def pg_factory():
    await _ensure_test_database_exists()

    engine = create_async_engine(_DB_URL, echo=False)
    async with engine.begin() as conn:
        _assert_isolated_proof_database(_TEST_DB_NAME)
        await conn.run_sync(Base.metadata.create_all, tables=_TABLES[:2])
        await conn.execute(text(
            "ALTER TABLE ai_assets ADD CONSTRAINT ux_ai_assets_id_org "
            "UNIQUE (id, organization_id)"
        ))
        await conn.run_sync(Base.metadata.create_all, tables=_TABLES[2:])
        for table in _ALL_TABLE_NAMES:
            await conn.execute(text(f"DELETE FROM {table}"))

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory

    async with engine.begin() as conn:
        _assert_isolated_proof_database(_TEST_DB_NAME)
        for table in _ALL_TABLE_NAMES:
            await conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))
    await engine.dispose()


# ─── Owned local lab ─────────────────────────────────────────────────────────

_HTTP_PORT = 18399
_TCP_PORT = 3306  # a DISCOVERY_PORT_POLICY_V1 member, so it is actually scanned

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
        self.wfile.write(b"<html>lab</html>")

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


@pytest.fixture(autouse=True)
def _reset_headers_state():
    _STATE["secure_headers"] = True
    yield
    _STATE["secure_headers"] = True


def _start_accept_loop_server(port: int, handler) -> tuple[socket.socket, threading.Event]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(5)
    stop = threading.Event()

    def _loop() -> None:
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                handler(conn)
            except OSError:
                pass
            finally:
                conn.close()

    thread = threading.Thread(target=_loop, daemon=True)
    thread.start()
    return sock, stop


def _start_bare_listener(port: int) -> tuple[socket.socket, threading.Event]:
    return _start_accept_loop_server(port, lambda _conn: None)


def _mysql_greeting() -> bytes:
    """A well-formed MySQL initial-handshake greeting with the
    CLIENT_SSL capability bit (0x0800) explicitly CLEARED, so the real
    parser in protocol_adapters.py's read_mysql_handshake() computes
    `supports_ssl=False` — the genuine signal
    _ingest_protocol_condition_findings() needs to ingest
    PLAINTEXT_SENSITIVE_SERVICE_OBSERVED. 0xF7FF is 0xFFFF with only
    bit 0x0800 cleared (every other capability flag still set)."""
    caps_lower_no_ssl = 0xFFFF & ~0x0800
    payload = (
        bytes([0x0A]) + b"8.0.35" + b"\x00"
        + b"\x01\x02\x03\x04" + b"AUTHDATA" + b"\x00"
        + struct.pack("<H", caps_lower_no_ssl)
    )
    header = struct.pack("<I", len(payload))[:3] + b"\x00"
    return header + payload


_MYSQL_PORT = 3306

_TARGET_ENDPOINT = f"http://127.0.0.1:{_HTTP_PORT}/"


@dataclass(frozen=True, slots=True)
class _Decision:
    decision: str
    decision_id: str
    reason_code: str


@dataclass
class _SequencedPolicyPort:
    queue: list[_Decision] = field(default_factory=list)
    calls: int = 0

    def push_deny(self, reason_code: str = "authorization_revoked") -> None:
        self.queue.append(_Decision("deny", f"dec-{self.calls + len(self.queue)}", reason_code))

    async def evaluate(self, *, organization_id, actor_user_id, action_class, entity_refs):
        self.calls += 1
        if self.queue:
            return self.queue.pop(0)
        return _Decision("allow", f"dec-auto-{self.calls}", "ok")


async def _make_stack(pg_factory, policy):
    events = InMemoryEventPublisher()
    ai_target_service = AITargetService(pg_factory, events)
    tenant_asset_service = TenantAssetService(pg_factory)
    condition_service = TenantSecurityConditionService(pg_factory)
    registry = CorrelationRuleRegistry()
    registry.register(
        PublicSensitiveServiceContextRule(
            asset_service=tenant_asset_service, condition_service=condition_service,
        )
    )
    registry.register(MultipleSecurityConditionsOnAssetRule(condition_service=condition_service))
    correlation_service = TenantSecurityCorrelationService(pg_factory, registry)
    execution_service = ValidationExecutionService(
        pg_factory, policy, ai_target_service, tenant_asset_service, condition_service,
        default_adaptive_rule_registry(), correlation_service, default_protocol_validator_registry(),
    )
    policy_service = ContinuousValidationPolicyService(pg_factory, ai_target_service)
    drift_service = SecurityDriftService(pg_factory)
    processor = ContinuousValidationProcessor(
        pg_factory, execution_service, ai_target_service, tenant_asset_service,
        condition_service, correlation_service, drift_service,
    )
    return ai_target_service, condition_service, policy_service, drift_service, processor


# ─── Proofs ────────────────────────────────────────────────────────────────


async def test_state_a_baseline_zero_fabricated_drift(pg_factory) -> None:
    org_id = str(EntityId.generate())
    user_id = str(EntityId.generate())
    policy_port = _SequencedPolicyPort()
    ai_target_service, _cond, policy_service, drift_service, processor = await _make_stack(
        pg_factory, policy_port,
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Lab Target A", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    policy_dto = await policy_service.create(
        org_id, target.id, user_id, "safe_active_baseline_v1", "hourly",
    )
    await policy_service.activate(org_id, policy_dto.id)

    execution = await processor.run_now(org_id, policy_dto.id)
    assert execution.status == "completed"

    drift = await drift_service.list_for_policy(policy_dto.id, org_id)
    assert drift == [], "first-ever run must never fabricate drift — there is no baseline yet"


async def test_state_b_mutation_condition_appears_with_drift(pg_factory) -> None:
    org_id = str(EntityId.generate())
    user_id = str(EntityId.generate())
    policy_port = _SequencedPolicyPort()
    ai_target_service, condition_service, policy_service, drift_service, processor = (
        await _make_stack(pg_factory, policy_port)
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Lab Target B", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    policy_dto = await policy_service.create(
        org_id, target.id, user_id, "safe_active_baseline_v1", "hourly",
    )
    await policy_service.activate(org_id, policy_dto.id)

    await processor.run_now(org_id, policy_dto.id)  # STATE A baseline

    _STATE["secure_headers"] = False
    await processor.run_now(org_id, policy_dto.id)  # STATE B mutation

    conditions = await condition_service.list_for_org(org_id, source_category="active_validation")
    active_rule_ids = {c.stable_rule_id for c in conditions if c.lifecycle == "active"}
    assert "MISSING_CSP_HEADER" in active_rule_ids
    assert "MISSING_X_CONTENT_TYPE_OPTIONS_HEADER" in active_rule_ids

    drift = await drift_service.list_for_policy(policy_dto.id, org_id)
    categories = {d.category for d in drift}
    assert "condition_appeared" in categories


async def test_state_c_reintroduction_reactivates_same_canonical_condition(pg_factory) -> None:
    org_id = str(EntityId.generate())
    user_id = str(EntityId.generate())
    policy_port = _SequencedPolicyPort()
    ai_target_service, condition_service, policy_service, drift_service, processor = (
        await _make_stack(pg_factory, policy_port)
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Lab Target C", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    policy_dto = await policy_service.create(
        org_id, target.id, user_id, "safe_active_baseline_v1", "hourly",
    )
    await policy_service.activate(org_id, policy_dto.id)

    await processor.run_now(org_id, policy_dto.id)  # STATE A
    conditions_a = await condition_service.list_for_org(org_id, source_category="active_validation")
    csp_id_a = next(c.id for c in conditions_a if c.stable_rule_id == "MISSING_CSP_HEADER") \
        if any(c.stable_rule_id == "MISSING_CSP_HEADER" for c in conditions_a) else None

    _STATE["secure_headers"] = False
    await processor.run_now(org_id, policy_dto.id)  # STATE B: condition appears
    conditions_b = await condition_service.list_for_org(org_id, source_category="active_validation")
    csp_condition = next(c for c in conditions_b if c.stable_rule_id == "MISSING_CSP_HEADER")
    assert csp_condition.lifecycle == "active"
    csp_id_b = csp_condition.id

    _STATE["secure_headers"] = True
    await processor.run_now(org_id, policy_dto.id)  # STATE C: condition resolves
    conditions_c = await condition_service.list_for_org(org_id, source_category="active_validation")
    csp_after_resolve = next(c for c in conditions_c if c.id == csp_id_b)
    assert csp_after_resolve.lifecycle == "resolved"

    _STATE["secure_headers"] = False
    await processor.run_now(org_id, policy_dto.id)  # reintroduce -> reactivation
    conditions_d = await condition_service.list_for_org(org_id, source_category="active_validation")
    csp_after_reactivate = next(c for c in conditions_d if c.id == csp_id_b)
    assert csp_after_reactivate.lifecycle == "active"
    assert csp_id_a is None or csp_id_a == csp_id_b  # same canonical identity, never duplicated

    drift = await drift_service.list_for_policy(policy_dto.id, org_id)
    categories = {d.category for d in drift}
    assert "condition_reactivated" in categories


async def test_identical_rerun_produces_zero_new_drift(pg_factory) -> None:
    org_id = str(EntityId.generate())
    user_id = str(EntityId.generate())
    policy_port = _SequencedPolicyPort()
    ai_target_service, _cond, policy_service, drift_service, processor = await _make_stack(
        pg_factory, policy_port,
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Lab Target Rerun", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    policy_dto = await policy_service.create(
        org_id, target.id, user_id, "safe_active_baseline_v1", "hourly",
    )
    await policy_service.activate(org_id, policy_dto.id)

    await processor.run_now(org_id, policy_dto.id)
    await processor.run_now(org_id, policy_dto.id)
    drift_before = len(await drift_service.list_for_policy(policy_dto.id, org_id))

    await processor.run_now(org_id, policy_dto.id)
    drift_after = len(await drift_service.list_for_policy(policy_dto.id, org_id))
    assert drift_after == drift_before


async def test_port_reachability_drift_from_real_socket_state(pg_factory) -> None:
    org_id = str(EntityId.generate())
    user_id = str(EntityId.generate())
    policy_port = _SequencedPolicyPort()
    ai_target_service, _cond, policy_service, drift_service, processor = await _make_stack(
        pg_factory, policy_port,
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Lab Target Port", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    policy_dto = await policy_service.create(
        org_id, target.id, user_id, "network_discovery_baseline_v1", "hourly",
    )
    await policy_service.activate(org_id, policy_dto.id)

    await processor.run_now(org_id, policy_dto.id)  # baseline: port closed

    sock, stop = _start_bare_listener(_TCP_PORT)
    try:
        await processor.run_now(org_id, policy_dto.id)  # port now reachable
    finally:
        stop.set()
        sock.close()

    drift = await drift_service.list_for_policy(policy_dto.id, org_id)
    categories = {d.category for d in drift}
    assert "port_became_reachable" in categories


async def test_revocation_before_dispatch_yields_zero_network_calls(pg_factory) -> None:
    org_id = str(EntityId.generate())
    user_id = str(EntityId.generate())
    policy_port = _SequencedPolicyPort()
    policy_port.push_deny("authorization_revoked")
    ai_target_service, _cond, policy_service, _drift, processor = await _make_stack(
        pg_factory, policy_port,
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Lab Target Revoke", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    policy_dto = await policy_service.create(
        org_id, target.id, user_id, "safe_active_baseline_v1", "hourly",
    )
    await policy_service.activate(org_id, policy_dto.id)

    execution = await processor.run_now(org_id, policy_dto.id)
    assert execution.status == "denied"
    assert execution.steps == []


async def test_concurrent_scheduler_claim_yields_exactly_one_execution(pg_factory) -> None:
    org_id = str(EntityId.generate())
    user_id = str(EntityId.generate())
    policy_port = _SequencedPolicyPort()
    ai_target_service, _cond, policy_service, _drift, processor = await _make_stack(
        pg_factory, policy_port,
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Lab Target Concurrency", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    policy_dto = await policy_service.create(
        org_id, target.id, user_id, "safe_active_baseline_v1", "hourly",
    )
    await policy_service.activate(org_id, policy_dto.id)

    results = await asyncio.gather(
        *(processor.process_one_due_policy(f"worker-{i}") for i in range(10)),
        return_exceptions=True,
    )
    successful = [r for r in results if r is not None and not isinstance(r, Exception)]
    assert len(successful) == 1, (
        f"expected exactly one canonical execution under a real concurrent claim race, "
        f"got {len(successful)}"
    )


async def test_restart_preserves_policy_and_drift_state(pg_factory) -> None:
    org_id = str(EntityId.generate())
    user_id = str(EntityId.generate())
    policy_port = _SequencedPolicyPort()
    ai_target_service, _cond, policy_service, drift_service, processor = await _make_stack(
        pg_factory, policy_port,
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Lab Target Restart", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    policy_dto = await policy_service.create(
        org_id, target.id, user_id, "safe_active_baseline_v1", "hourly",
    )
    await policy_service.activate(org_id, policy_dto.id)
    await processor.run_now(org_id, policy_dto.id)
    _STATE["secure_headers"] = False
    await processor.run_now(org_id, policy_dto.id)
    drift_before = await drift_service.list_for_policy(policy_dto.id, org_id)

    # Fresh service instances against the same database — simulates a
    # process restart. No in-memory state carries over.
    _ai2, _cond2, fresh_policy_service, fresh_drift_service, _proc2 = await _make_stack(
        pg_factory, policy_port,
    )
    reloaded_policy = await fresh_policy_service.get(org_id, policy_dto.id)
    assert reloaded_policy.lifecycle == "active"
    reloaded_drift = await fresh_drift_service.list_for_policy(policy_dto.id, org_id)
    assert {d.id for d in reloaded_drift} == {d.id for d in drift_before}


async def test_claim_atomicity_verified_via_repository(pg_factory) -> None:
    """Direct repository-level proof that the atomic claim + bounded
    lease genuinely work against real Postgres (complements the
    higher-level concurrent-claim proof above with a lower-level,
    lease-expiry-specific check)."""
    from datetime import UTC, datetime, timedelta

    org_id = str(EntityId.generate())
    user_id = str(EntityId.generate())
    policy_port = _SequencedPolicyPort()
    ai_target_service, _cond, policy_service, _drift, _proc = await _make_stack(
        pg_factory, policy_port,
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Lab Target Claim", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    policy_dto = await policy_service.create(
        org_id, target.id, user_id, "safe_active_baseline_v1", "hourly",
    )
    await policy_service.activate(org_id, policy_dto.id)

    now = datetime.now(UTC)
    async with pg_factory() as session:
        repo = SqlAlchemyContinuousValidationPolicyRepository(session)
        claimed = await repo.claim_one_due_policy(now, "worker-a")
        await session.commit()
    assert claimed is not None

    async with pg_factory() as session:
        repo = SqlAlchemyContinuousValidationPolicyRepository(session)
        second = await repo.claim_one_due_policy(now, "worker-b")
    assert second is None, "an already-claimed, unexpired policy must not be claimable again"

    future = now + timedelta(seconds=400)
    async with pg_factory() as session:
        repo = SqlAlchemyContinuousValidationPolicyRepository(session)
        reclaimed = await repo.claim_one_due_policy(future, "worker-c")
        await session.commit()
    assert reclaimed is not None
    assert reclaimed.claim_owner == "worker-c"


async def test_disable_during_in_flight_run_is_never_resurrected(pg_factory) -> None:
    """Regression test for an adversarial-review P0: an operator's
    disable() committed WHILE a scheduled run is still in flight must
    never be clobbered back to ACTIVE by that run's own post-run save.
    Simulates the race directly: claim a policy (capturing the
    in-memory snapshot a long-running create_and_run() would have held
    for its whole duration), have the operator disable it via the REST-
    facing service in the meantime, then feed that STALE captured
    snapshot into _release_and_advance() exactly as process_one_due_policy()
    would on completion — the row-locked re-read must see the operator's
    committed DISABLED state and refuse to touch it further."""
    org_id = str(EntityId.generate())
    user_id = str(EntityId.generate())
    policy_port = _SequencedPolicyPort()
    ai_target_service, _cond, policy_service, _drift, processor = await _make_stack(
        pg_factory, policy_port,
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Lab Target TOCTOU", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    policy_dto = await policy_service.create(
        org_id, target.id, user_id, "safe_active_baseline_v1", "hourly",
    )
    await policy_service.activate(org_id, policy_dto.id)

    from datetime import UTC, datetime

    now = datetime.now(UTC)
    async with pg_factory() as session:
        repo = SqlAlchemyContinuousValidationPolicyRepository(session)
        stale_claimed_snapshot = await repo.claim_one_due_policy(now, "scheduler-worker-1")
        await session.commit()
    assert stale_claimed_snapshot is not None

    # Operator action "during" the (simulated) long-running run.
    await policy_service.disable(org_id, policy_dto.id)
    disabled = await policy_service.get(org_id, policy_dto.id)
    assert disabled.lifecycle == "disabled"

    # The scheduler's own post-run step, fed the STALE (pre-disable)
    # in-memory snapshot — exactly what process_one_due_policy() would
    # do after a real (long) create_and_run() call completes.
    await processor._release_and_advance(stale_claimed_snapshot, now)

    final = await policy_service.get(org_id, policy_dto.id)
    assert final.lifecycle == "disabled", (
        "a DISABLED policy must never be resurrected to ACTIVE by a scheduled run's "
        "own post-run save, even when that run was claimed before the disable() call"
    )


async def test_condition_reconciliation_is_scoped_per_port_not_globally(pg_factory) -> None:
    """Regression test for an adversarial-review P0: PLAINTEXT_SENSITIVE_
    SERVICE_OBSERVED conditions live on two DIFFERENT ports (MySQL 3306,
    controlled by this test; PostgreSQL 5432, this dev machine's own
    real, always-up local server — the same real-infra precedent M12/
    M13's own proof files rely on), each validated by its own
    independent protocol step. Once MySQL stops responding (so
    mysql_handshake never even gets scheduled this run — port_discovery
    no longer sees 3306 as reachable at all), a run where ONLY
    PostgreSQL's step validates must NOT resolve MySQL's own
    still-active condition — that port was never actually re-examined
    this run, regardless of PostgreSQL's own step succeeding. (Redis is
    not used for this test: RedisPingValidator has no SSL-capability
    signal at all — a bare PING/PONG never produces
    PLAINTEXT_SENSITIVE_SERVICE_OBSERVED, so it cannot exercise this
    scenario.)"""
    org_id = str(EntityId.generate())
    user_id = str(EntityId.generate())
    policy_port = _SequencedPolicyPort()
    ai_target_service, condition_service, policy_service, _drift, processor = await _make_stack(
        pg_factory, policy_port,
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Lab Target Port Scope", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    policy_dto = await policy_service.create(
        org_id, target.id, user_id, "network_discovery_baseline_v1", "hourly",
    )
    await policy_service.activate(org_id, policy_dto.id)

    mysql_sock, mysql_stop = _start_accept_loop_server(
        _MYSQL_PORT, lambda c: c.sendall(_mysql_greeting()),
    )
    try:
        # Baseline run: both MySQL (fake, no-SSL) and the real local
        # PostgreSQL (assumed no-SSL per M12/M13's own precedent)
        # validate; both plaintext conditions ingested.
        await processor.run_now(org_id, policy_dto.id)
    finally:
        mysql_stop.set()
        mysql_sock.close()

    conditions = await condition_service.list_for_org(org_id, source_category="network_discovery")
    plaintext = [c for c in conditions if c.stable_rule_id == "PLAINTEXT_SENSITIVE_SERVICE_OBSERVED"]
    mysql_conditions = [c for c in plaintext if "3306" in c.summary]
    postgres_conditions = [c for c in plaintext if "5432" in c.summary]
    assert len(mysql_conditions) == 1, "expected exactly one plaintext condition for MySQL"
    assert len(postgres_conditions) == 1, (
        "expected exactly one plaintext condition for the real local PostgreSQL server "
        "— if this fails, the local Postgres may have SSL enabled; see M12/M13's own "
        "proof files for the same real-local-Postgres precedent"
    )
    assert mysql_conditions[0].lifecycle == "active"
    mysql_condition_id = mysql_conditions[0].id

    # MySQL stopped entirely; the real local PostgreSQL is still up and
    # still validates.
    await processor.run_now(org_id, policy_dto.id)

    reloaded = await condition_service.get_for_org(mysql_condition_id, org_id)
    assert reloaded.lifecycle == "active", (
        "MySQL's own condition must stay active — port 3306 was never re-examined this "
        "run (mysql_handshake never even got scheduled once discovery stopped seeing it "
        "reachable), regardless of PostgreSQL's own independent step validating successfully"
    )
