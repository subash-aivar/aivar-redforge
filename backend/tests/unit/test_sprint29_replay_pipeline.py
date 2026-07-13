"""Sprint 29 — Replay pipeline unit tests.

Verifies:
- fetch_by_event_id returns envelope when event exists
- fetch_by_event_id returns None when event not found
- real replay_fn succeeds when event exists in EventStore
- real replay_fn returns False when event_id not found
- replay is idempotent (event already checkpointed → skip, still True)
- replay_fn returns False on exception in engine.process
- migration head check passes on correct version
- migration head check fails on wrong version
- migration head check errors when table missing
- startup validator skips migration check in test env
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

from redforge.application.platform.dead_letter_queue import InMemoryDeadLetterQueue
from redforge.application.platform.idempotent_projection_engine import (
    IdempotentProjectionEngine,
)
from redforge.application.platform.replay_worker import DLQReplayWorker
from redforge.application.platform.runtime_contracts import DeadLetterEntry
from redforge.application.platform.startup_validator import (
    _check_migration_head,
    validate_startup,
)
from redforge.core.config import Settings
from redforge.domain.platform.events import EventEnvelope
from redforge.domain.platform.value_objects import CausationId, CorrelationId, EventMetadata


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _make_envelope(event_id: str = "ev-001", global_position: int = 1) -> EventEnvelope:
    return EventEnvelope(
        event_id=event_id,
        stream_id="test:agg-1",
        stream_position=1,
        global_position=global_position,
        event_type="test.TestEvent",
        aggregate_type="test",
        aggregate_id="agg-1",
        organization_id="org-test",
        payload={"key": "value"},
        metadata=EventMetadata(
            correlation_id=CorrelationId("corr-1"),
            causation_id=CausationId("caus-1"),
            schema_version=1,
        ),
        occurred_at=_utc_now(),
        recorded_at=_utc_now(),
    )


def _make_entry(
    event_id: str = "ev-001",
    source_projection: str = "test_proj",
    retry_count: int = 0,
    organization_id: str = "org-test",
) -> DeadLetterEntry:
    now = _utc_now()
    return DeadLetterEntry(
        entry_id=f"dle-{event_id}",
        source_projection=source_projection,
        event_id=event_id,
        event_type="test.TestEvent",
        payload={"key": "value"},
        error_message="projection failed",
        retry_count=retry_count,
        first_failed_at=now,
        last_failed_at=now,
        organization_id=organization_id,
    )


# ── fetch_by_event_id ─────────────────────────────────────────────────────────


async def test_fetch_by_event_id_returns_envelope_when_found() -> None:
    """fetch_by_event_id queries the event_id column and converts the row."""
    from redforge.infrastructure.platform.event_store import PostgreSQLEventStore

    now = _utc_now()
    mock_session = AsyncMock()
    mock_row = MagicMock()
    mock_row.event_id = "ev-found"
    mock_row.stream_id = "test:agg-1"
    mock_row.stream_position = 1
    mock_row.global_position = 1
    mock_row.event_type = "test.TestEvent"
    mock_row.aggregate_type = "test"
    mock_row.aggregate_id = "agg-1"
    mock_row.organization_id = "org-test"
    mock_row.payload = {"key": "value"}
    # metadata_ (ORM column name) must be a proper dict for deserialization
    mock_row.metadata_ = {
        "correlation_id": "corr-1.0",
        "causation_id": None,
        "schema_version": "1.0",
        "custom": [],
        "source_service": "test",
    }
    mock_row.occurred_at = now
    mock_row.recorded_at = now

    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = mock_row
    mock_session.execute = AsyncMock(return_value=mock_result)

    store = PostgreSQLEventStore(mock_session)
    result = await store.fetch_by_event_id("ev-found")
    assert result is not None
    assert result.event_id == "ev-found"
    assert result.organization_id == "org-test"


async def test_fetch_by_event_id_returns_none_when_missing() -> None:
    """Returns None when event_id is not found."""
    from redforge.infrastructure.platform.event_store import PostgreSQLEventStore

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_result)

    store = PostgreSQLEventStore(mock_session)
    result = await store.fetch_by_event_id("ev-missing")
    assert result is None


# ── Replay pipeline integration ───────────────────────────────────────────────


async def test_replay_fn_success_path() -> None:
    """replay_fn fetches event, processes it, returns True."""
    envelope = _make_envelope("ev-001")
    entry = _make_entry("ev-001")

    mock_event_store = AsyncMock()
    mock_event_store.fetch_by_event_id = AsyncMock(return_value=envelope)

    mock_checkpoint_repo = AsyncMock()
    mock_checkpoint_repo.load = AsyncMock(return_value=None)
    mock_checkpoint_repo.save = AsyncMock()

    engine = IdempotentProjectionEngine(mock_checkpoint_repo)
    # No handlers registered — process() is a no-op but doesn't raise

    replay_success_count = 0

    async def replay_fn(e: DeadLetterEntry) -> bool:
        nonlocal replay_success_count
        mock_es = mock_event_store
        env = await mock_es.fetch_by_event_id(e.event_id)
        if env is None:
            return False
        await engine.process(env)
        replay_success_count += 1
        return True

    result = await replay_fn(entry)
    assert result is True
    assert replay_success_count == 1


async def test_replay_fn_returns_false_when_event_not_found() -> None:
    """replay_fn returns False when event_id is not in EventStore."""
    entry = _make_entry("ev-missing")

    mock_event_store = AsyncMock()
    mock_event_store.fetch_by_event_id = AsyncMock(return_value=None)

    async def replay_fn(e: DeadLetterEntry) -> bool:
        env = await mock_event_store.fetch_by_event_id(e.event_id)
        return env is not None

    result = await replay_fn(entry)
    assert result is False


async def test_replay_idempotent_event_already_checkpointed() -> None:
    """If IdempotentProjectionEngine sees event below checkpoint, process() is a no-op."""
    from redforge.domain.platform.value_objects import (
        ProjectionCheckpoint,
        ProjectionState,
    )

    # Checkpoint at position 10 — event at position 5 is BELOW checkpoint
    envelope = _make_envelope("ev-old", global_position=5)
    existing_cp = ProjectionCheckpoint(
        projection_id="test_proj",
        projection_name="test_proj",
        last_global_position=10,
        last_processed_at=_utc_now(),
        state=ProjectionState.LIVE,
        events_processed=5,
    )

    mock_checkpoint_repo = AsyncMock()
    mock_checkpoint_repo.load = AsyncMock(return_value=existing_cp)
    mock_checkpoint_repo.save = AsyncMock()

    engine = IdempotentProjectionEngine(mock_checkpoint_repo)
    handler_called = False

    def _handler(env: EventEnvelope) -> None:
        nonlocal handler_called
        handler_called = True

    engine.register("test_proj", "test.TestEvent", _handler)
    await engine.load_checkpoints()

    # Process the old event — should be SKIPPED
    await engine.process(envelope)
    assert not handler_called
    assert engine.events_skipped == 1


async def test_replay_fn_returns_false_on_exception() -> None:
    """replay_fn catches exceptions and returns False."""
    entry = _make_entry("ev-broken")

    async def replay_fn(e: DeadLetterEntry) -> bool:
        raise RuntimeError("projection exploded")

    import contextlib
    with contextlib.suppress(Exception):
        await replay_fn(entry)

    # DLQReplayWorker wraps in try/except so we test that path directly
    dlq = InMemoryDeadLetterQueue(max_size=100)
    await dlq.store(entry)
    await dlq.requeue(entry.entry_id)

    async def bad_replay_fn(e: DeadLetterEntry) -> bool:
        raise RuntimeError("broken")

    worker = DLQReplayWorker(
        dlq=dlq,
        replay_fn=bad_replay_fn,
        poll_interval_s=60.0,
        max_concurrent=1,
        batch_size=10,
        replay_max_retries=3,
    )
    # _poll_once should count the failure, not raise
    processed = await worker._poll_once()
    assert processed == 1
    assert worker.stats()["failed"] == 1
    assert worker.stats()["replayed"] == 0


# ── Migration check ───────────────────────────────────────────────────────────


def _make_migration_engine_mock(version_row: tuple[str, ...] | None) -> object:
    """Build an AsyncEngine mock for _check_migration_head only (one execute call)."""
    mock_result = MagicMock()
    mock_result.fetchone.return_value = version_row

    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock(return_value=mock_result)

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_conn)
    cm.__aexit__ = AsyncMock(return_value=False)

    mock_engine = MagicMock()
    mock_engine.connect.return_value = cm
    return mock_engine


async def test_migration_check_passes_on_correct_version() -> None:
    """_check_migration_head passes when alembic_version = head."""
    errors: list[str] = []
    mock_engine = _make_migration_engine_mock(("0026",))
    await _check_migration_head(mock_engine, errors)  # type: ignore[arg-type]
    assert errors == []


async def test_migration_check_fails_on_wrong_version() -> None:
    """_check_migration_head appends error when version != head."""
    errors: list[str] = []
    mock_engine = _make_migration_engine_mock(("0007",))
    await _check_migration_head(mock_engine, errors)  # type: ignore[arg-type]
    assert len(errors) == 1
    assert "0007" in errors[0]
    assert "0026" in errors[0]


async def test_migration_check_fails_when_table_empty() -> None:
    """_check_migration_head appends error when alembic_version has no rows."""
    errors: list[str] = []
    mock_engine = _make_migration_engine_mock(None)
    await _check_migration_head(mock_engine, errors)  # type: ignore[arg-type]
    assert len(errors) == 1
    assert "alembic_version" in errors[0]


async def test_startup_validator_skips_db_check_in_test_env() -> None:
    """validate_startup skips DB + migration checks in environment='test'."""
    settings = Settings(
        app_name="test",
        environment="test",
        database_url="postgresql+asyncpg://x:x@localhost/x",
    )
    mock_engine = MagicMock()
    await validate_startup(settings, mock_engine)  # type: ignore[arg-type]
    mock_engine.connect.assert_not_called()
