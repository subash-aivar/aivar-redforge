"""Owned local operations lab + real-PostgreSQL concurrency/ordering
proof for M15 — Security Operations Command Center.

Runs against a dedicated, self-created database
(`redforge_security_operations_proof_test`), never the shared dev
database. `_assert_isolated_proof_database()` — the same guard M12-M14's
own proof files introduced — is applied before every destructive
command.

This file proves M15's OWN new guarantees specifically (event merge,
cursor resume, tenant isolation, runtime-transition dedup, ordering
under the commit-visibility safety margin). It deliberately does not
re-prove the underlying M11-M14 validation/discovery/drift mechanics
themselves — those already have their own dedicated, passing
PostgreSQL proof suites (see test_protocol_aware_service_validation_
postgres_proof.py and test_continuous_validation_lab_proof.py).

Proves:
  1. A real ValidationExecution's own durable events (created/started)
     are visible through SecurityOperationsStreamService.poll().
  2. A ContinuousValidationPolicy's lifecycle transitions (create/
     activate/pause) appear as PolicyLifecycle operational events.
  3. Cursor resume: reconnecting with the last delivered cursor
     strictly excludes everything already seen, no duplicates.
  4. Restart durability: a FRESH SecurityOperationsStreamService
     instance (simulating a process restart) reads back the exact
     same event history from the database.
  5. Cross-tenant isolation: org B's poll() never contains org A's
     execution/policy events; a platform-wide runtime transition IS
     broadcast to both (the one deliberate exception, since runtime
     components are not tenant data).
  6. Runtime transition dedup: many genuinely concurrent
     record_transition_if_changed() calls for the identical
     HEALTHY->UNHEALTHY flip converge on exactly ONE recorded
     transition row, proven via `asyncio.gather()`, not a sequential
     re-run.
  7. Ordering under the commit-visibility safety margin: an
     event with an EARLIER occurred_at that commits LATER than a
     second event with a LATER occurred_at is never permanently
     skipped — both eventually appear in correct chronological cursor
     order once the visibility lag elapses.
"""

from __future__ import annotations

import asyncio
import http.server
import os
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.ai_targets import AITargetService
from redforge.application.continuous_validation.policy_service import (
    ContinuousValidationPolicyService,
)
from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.security_conditions.service import TenantSecurityConditionService
from redforge.application.security_correlation.rules import CorrelationRuleRegistry
from redforge.application.security_correlation.service import TenantSecurityCorrelationService
from redforge.application.security_operations import stream_service as stream_service_module
from redforge.application.security_operations.stream_service import (
    SecurityOperationsStreamService,
)
from redforge.application.validation_execution import network_adapters
from redforge.application.validation_execution.adaptive_rules import default_adaptive_rule_registry
from redforge.application.validation_execution.execution_service import ValidationExecutionService
from redforge.application.validation_execution.protocol_validators import (
    default_protocol_validator_registry,
)
from redforge.domain.validation_execution.execution_event import ExecutionEvent
from redforge.domain.validation_execution.value_objects import AddressClass, ExecutionEventType
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
    RuntimeComponentHealthStateModel,
    RuntimeComponentHealthTransitionModel,
)
from redforge.infrastructure.database.models.validation_execution import (
    ValidationExecutionEventModel,
    ValidationExecutionModel,
    ValidationExecutionStepModel,
)
from redforge.infrastructure.database.repositories.runtime_health_repository import (
    SqlAlchemyRuntimeHealthRepository,
)
from redforge.infrastructure.database.repositories.validation_execution.event_repository import (
    SqlAlchemyExecutionEventRepository,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio

_TEST_DB_NAME = "redforge_security_operations_proof_test"
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
    RuntimeComponentHealthStateModel.__table__,
    RuntimeComponentHealthTransitionModel.__table__,
]

_ALL_TABLE_NAMES = (
    "runtime_component_health_transitions",
    "runtime_component_health_state",
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
    print(f"[proof-db-guard] destructive command target database: {target_db_name!r}")
    assert target_db_name == _TEST_DB_NAME, (
        f"REFUSING destructive command: target database {target_db_name!r} is not the "
        f"isolated proof database {_TEST_DB_NAME!r}."
    )


@pytest.fixture(autouse=True)
def _allow_loopback_for_local_test_server(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        network_adapters, "ALLOWED_ADDRESS_CLASSES",
        frozenset({AddressClass.PUBLIC, AddressClass.LOOPBACK}),
    )


@pytest.fixture(autouse=True)
def _disable_visibility_lag_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Most tests in this file want instant visibility; the ONE test
    that specifically proves the lag's anti-skip property
    (test_ordering_survives_out_of_order_commit_under_visibility_lag)
    restores the real value itself for its own duration."""
    monkeypatch.setattr(stream_service_module, "EVENT_VISIBILITY_LAG_SECONDS", 0.0)


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


# ─── Owned local lab (loopback only) ────────────────────────────────────────

_PORT = 18499


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


_TARGET_ENDPOINT = f"http://127.0.0.1:{_PORT}/"


@dataclass(frozen=True, slots=True)
class _Decision:
    decision: str
    decision_id: str
    reason_code: str


class _AlwaysAllowPolicyPort:
    async def evaluate(self, *, organization_id, actor_user_id, action_class, entity_refs):
        return _Decision("allow", "dec-1", "ok")


def _build_execution_service(
    session_factory,
) -> tuple[ValidationExecutionService, AITargetService]:
    ai_target_service = AITargetService(session_factory, InMemoryEventPublisher())
    tenant_asset_service = TenantAssetService(session_factory)
    condition_service = TenantSecurityConditionService(session_factory)
    correlation_service = TenantSecurityCorrelationService(session_factory, CorrelationRuleRegistry())
    execution_service = ValidationExecutionService(
        session_factory, _AlwaysAllowPolicyPort(),  # type: ignore[arg-type]
        ai_target_service, tenant_asset_service, condition_service,
        default_adaptive_rule_registry(), correlation_service,
        default_protocol_validator_registry(),
    )
    return execution_service, ai_target_service


async def test_execution_events_visible_through_stream_poll(pg_factory) -> None:
    org_id = str(EntityId.generate())
    execution_service, ai_target_service = _build_execution_service(pg_factory)
    target = await ai_target_service.register(
        organization_id=org_id, name="Owned Test Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    await execution_service.create_and_run(org_id, str(target.id), str(EntityId.generate()))

    stream = SecurityOperationsStreamService(pg_factory)
    events = await stream.poll(org_id, None)
    titles = [e.title for e in events]
    assert "Validation created" in titles
    assert "Validation started" in titles


async def test_policy_lifecycle_visible_through_stream_poll(pg_factory) -> None:
    org_id = str(EntityId.generate())
    _execution_service, ai_target_service = _build_execution_service(pg_factory)
    target = await ai_target_service.register(
        organization_id=org_id, name="Owned Test Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    policy_service = ContinuousValidationPolicyService(pg_factory, ai_target_service)
    policy = await policy_service.create(org_id, str(target.id), str(EntityId.generate()), "safe_active_baseline_v1", "hourly")
    await policy_service.activate(org_id, policy.id)
    await policy_service.pause(org_id, policy.id)

    stream = SecurityOperationsStreamService(pg_factory)
    events = await stream.poll(org_id, None)
    titles = [e.title for e in events]
    assert "Continuous validation policy created" in titles
    assert "Continuous validation policy activated" in titles
    assert "Continuous validation policy paused" in titles


async def test_resume_strictly_after_cursor_no_duplicates(pg_factory) -> None:
    org_id = str(EntityId.generate())
    execution_service, ai_target_service = _build_execution_service(pg_factory)
    target = await ai_target_service.register(
        organization_id=org_id, name="Owned Test Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    await execution_service.create_and_run(org_id, str(target.id), str(EntityId.generate()))

    stream = SecurityOperationsStreamService(pg_factory)
    first_batch = await stream.poll(org_id, None)
    assert first_batch
    last_cursor = first_batch[-1].cursor

    await execution_service.create_and_run(org_id, str(target.id), str(EntityId.generate()))
    resumed = await stream.poll(org_id, last_cursor)
    seen = {e.cursor for e in first_batch}
    assert resumed
    for e in resumed:
        assert e.cursor not in seen


async def test_restart_preserves_full_event_history(pg_factory) -> None:
    org_id = str(EntityId.generate())
    execution_service, ai_target_service = _build_execution_service(pg_factory)
    target = await ai_target_service.register(
        organization_id=org_id, name="Owned Test Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    await execution_service.create_and_run(org_id, str(target.id), str(EntityId.generate()))

    stream_before_restart = SecurityOperationsStreamService(pg_factory)
    before = await stream_before_restart.poll(org_id, None)

    # Simulate a process restart: a brand new instance, no shared in-memory
    # state, reading from the same durable database.
    stream_after_restart = SecurityOperationsStreamService(pg_factory)
    after = await stream_after_restart.poll(org_id, None)

    assert [e.cursor for e in before] == [e.cursor for e in after]
    assert len(after) > 0


async def test_cross_tenant_isolation_and_runtime_broadcast(pg_factory) -> None:
    org_a = str(EntityId.generate())
    org_b = str(EntityId.generate())
    execution_service, ai_target_service = _build_execution_service(pg_factory)
    target_a = await ai_target_service.register(
        organization_id=org_a, name="Owned Test Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    await execution_service.create_and_run(org_a, str(target_a.id), str(EntityId.generate()))

    async with pg_factory() as session:
        repo = SqlAlchemyRuntimeHealthRepository(session)
        await repo.record_transition_if_changed(
            transition_id=str(EntityId.generate()), component_id="database",
            new_status="healthy", now=datetime.now(UTC),
        )
        recorded = await repo.record_transition_if_changed(
            transition_id=str(EntityId.generate()), component_id="database",
            new_status="unhealthy", now=datetime.now(UTC),
        )
        await session.commit()
    assert recorded == "healthy"

    stream = SecurityOperationsStreamService(pg_factory)
    events_a = await stream.poll(org_a, None)
    events_b = await stream.poll(org_b, None)

    assert any(e.title == "Validation created" for e in events_a)
    assert not any(e.title == "Validation created" for e in events_b)

    # Runtime health is platform-wide, not tenant data — it IS broadcast
    # to every organization's feed, a deliberate, documented exception.
    assert any(e.source_domain.value == "runtime" for e in events_a)
    assert any(e.source_domain.value == "runtime" for e in events_b)


# ─── PostgreSQL concurrency proof ───────────────────────────────────────────


async def test_concurrent_runtime_transition_recorded_exactly_once(pg_factory) -> None:
    async with pg_factory() as seed_session:
        repo = SqlAlchemyRuntimeHealthRepository(seed_session)
        await repo.record_transition_if_changed(
            transition_id=str(EntityId.generate()), component_id="dlq",
            new_status="healthy", now=datetime.now(UTC),
        )
        await seed_session.commit()

    async def _attempt() -> str | None:
        async with pg_factory() as session:
            repo = SqlAlchemyRuntimeHealthRepository(session)
            result = await repo.record_transition_if_changed(
                transition_id=str(EntityId.generate()), component_id="dlq",
                new_status="unhealthy", now=datetime.now(UTC),
            )
            await session.commit()
            return result

    results = await asyncio.gather(*[_attempt() for _ in range(8)])
    recorded = [r for r in results if r is not None]
    assert len(recorded) == 1, (
        f"expected exactly one concurrent caller to record the transition, got {len(recorded)}"
    )


async def test_ordering_survives_out_of_order_commit_under_visibility_lag(
    pg_factory, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The direct proof of the commit-visibility safety margin's reason
    to exist: event A (earlier occurred_at) commits AFTER event B (later
    occurred_at). A poll() taken between B's commit and A's commit must
    show neither (both too recent under a real lag) rather than
    permanently skipping A once its cursor position is superseded. Both
    events use the SAME projected event type (STEP_FAILED, arbitrarily
    chosen as one the real dispatch is unlikely to also emit for this
    owned local target) so their own computed cursors — not fragile
    title matching — are the basis for the ordering assertion."""
    monkeypatch.setattr(stream_service_module, "EVENT_VISIBILITY_LAG_SECONDS", 2.0)

    org_id = str(EntityId.generate())
    execution_service, ai_target_service = _build_execution_service(pg_factory)
    target = await ai_target_service.register(
        organization_id=org_id, name="Owned Test Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    execution = await execution_service.create_and_run(
        org_id, str(target.id), str(EntityId.generate()),
    )
    execution_entity_id = EntityId.from_string(execution.id)
    org_entity_id = EntityId.from_string(org_id)

    now = datetime.now(UTC)
    event_a = ExecutionEvent(
        id=EntityId.generate(), execution_id=execution_entity_id, organization_id=org_entity_id,
        sequence=9001, event_type=ExecutionEventType.STEP_FAILED, payload={"step_type": "race_a"},
        occurred_at=now - timedelta(milliseconds=50),
    )
    event_b = ExecutionEvent(
        id=EntityId.generate(), execution_id=execution_entity_id, organization_id=org_entity_id,
        sequence=9002, event_type=ExecutionEventType.STEP_FAILED, payload={"step_type": "race_b"},
        occurred_at=now,
    )
    a_cursor = stream_service_module.make_cursor(event_a.occurred_at, "E", str(event_a.id))
    b_cursor = stream_service_module.make_cursor(event_b.occurred_at, "E", str(event_b.id))
    assert a_cursor < b_cursor, "test setup sanity: A's own cursor must sort before B's"

    session_a = pg_factory()
    await session_a.begin()
    repo_a = SqlAlchemyExecutionEventRepository(session_a)
    await repo_a.append(event_a)  # flushed, NOT committed — invisible to other sessions

    async with pg_factory() as session_b:
        repo_b = SqlAlchemyExecutionEventRepository(session_b)
        await repo_b.append(event_b)
        await session_b.commit()  # B (later occurred_at) commits FIRST

    stream = SecurityOperationsStreamService(pg_factory)
    mid_race = await stream.poll(org_id, None)
    mid_race_cursors = {e.cursor for e in mid_race}
    assert b_cursor not in mid_race_cursors, (
        "B must not be visible yet — both events are too recent under the visibility lag"
    )
    assert a_cursor not in mid_race_cursors, "A is not even committed yet"

    await session_a.commit()
    await session_a.close()

    monkeypatch.setattr(stream_service_module, "EVENT_VISIBILITY_LAG_SECONDS", 0.0)
    settled = await stream.poll(org_id, None)
    settled_cursors = [e.cursor for e in settled]
    assert a_cursor in settled_cursors, "A must eventually become visible — never permanently skipped"
    assert b_cursor in settled_cursors, "B must eventually become visible once settled"
    assert settled_cursors.index(a_cursor) < settled_cursors.index(b_cursor), (
        "A (earlier occurred_at) must sort before B, despite committing after it"
    )
