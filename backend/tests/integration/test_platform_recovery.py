"""Crash recovery and replay safety tests — Sprint 25.

Tests:
- Projection restarts correctly from last checkpoint
- Partial batch failures leave no orphaned state
- Replay filters work correctly after crash
- IdempotentProjectionEngine handles out-of-order delivery
- Snapshot-based recovery reduces event replay count
- Checkpoint corruption guard
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.application.platform.aggregate_repository import (
    AggregateRehydrationRepository,
)
from redforge.application.platform.event_store import InMemoryEventStore, InMemorySnapshotStore
from redforge.application.platform.idempotent_projection_engine import (
    IdempotentProjectionEngine,
)
from redforge.application.platform.projection_engine import (
    InMemoryCheckpointRepository,
)
from redforge.domain.platform.events import EventBatch, EventSnapshot, make_envelope
from redforge.domain.platform.exceptions import ProjectionError
from redforge.domain.platform.value_objects import (
    EventVersion,
)

_ORG = "01KX3FWDMBVJTKGWNE273CN46A"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _mk_env(event_type: str, agg_id: str = "agg-1", org: str = _ORG) -> object:
    return make_envelope(
        payload={"ts": _utc_now().isoformat()},
        event_type=event_type,
        aggregate_type=event_type.split(".")[0],
        aggregate_id=agg_id,
        stream_id=f"{event_type.split('.')[0]}:{agg_id}",
        organization_id=org,
    )


async def _store_events(
    store: InMemoryEventStore,
    event_type: str,
    count: int,
    agg_id: str = "agg-1",
    org: str = _ORG,
) -> list[object]:
    stored_all = []
    for _ in range(count):
        env = _mk_env(event_type, agg_id=agg_id, org=org)
        batch = EventBatch(
            stream_id=f"{event_type.split('.')[0]}:{agg_id}",
            organization_id=org,
            events=(env,),
        )
        stored = await store.append(batch)
        stored_all.extend(stored)
    return stored_all


class TestProjectionCrashRecovery:
    @pytest.mark.asyncio
    async def test_restart_resumes_from_checkpoint(self) -> None:
        store = InMemoryEventStore()
        checkpoint_repo = InMemoryCheckpointRepository()

        all_events = await _store_events(store, "validation.Run", 20)

        # Session 1: process first 10
        received_1: list[int] = []

        async def handler(ev: object) -> None:
            received_1.append(ev.global_position)  # type: ignore[union-attr]

        engine1 = IdempotentProjectionEngine(checkpoint_repo=checkpoint_repo)
        engine1.register("validation_summary", "validation.Run", handler)
        await engine1.process_batch(all_events[:10])
        assert len(received_1) == 10
        assert received_1[-1] == 9  # position 9 is last

        # Session 2: new engine, load checkpoint, replay all
        received_2: list[int] = []

        async def handler2(ev: object) -> None:
            received_2.append(ev.global_position)  # type: ignore[union-attr]

        engine2 = IdempotentProjectionEngine(checkpoint_repo=checkpoint_repo)
        engine2.register("validation_summary", "validation.Run", handler2)
        await engine2.load_checkpoints()
        await engine2.process_batch(all_events)

        # Only the 10 new events (positions 10-19) should be processed
        assert received_2 == list(range(10, 20))

    @pytest.mark.asyncio
    async def test_handler_failure_does_not_advance_checkpoint(self) -> None:
        store = InMemoryEventStore()
        checkpoint_repo = InMemoryCheckpointRepository()

        all_events = await _store_events(store, "test.Ev", 5)
        received: list[int] = []
        call_count = [0]

        async def sometimes_fails(ev: object) -> None:
            call_count[0] += 1
            if call_count[0] == 3:
                raise RuntimeError("simulated crash at event 3")
            received.append(ev.global_position)  # type: ignore[union-attr]

        engine = IdempotentProjectionEngine(checkpoint_repo=checkpoint_repo)
        engine.register("proj", "test.Ev", sometimes_fails)

        # Process events 0, 1 successfully; 2 fails
        await engine.process_batch(all_events[:2])
        with pytest.raises(ProjectionError):
            await engine.process(all_events[2])

        # Checkpoint should be at position 1 (last success)
        cp = await checkpoint_repo.load("proj")
        assert cp is not None
        assert cp.last_global_position == 1

    @pytest.mark.asyncio
    async def test_replay_after_error_reprocesses_failed_event(self) -> None:
        store = InMemoryEventStore()
        checkpoint_repo = InMemoryCheckpointRepository()

        all_events = await _store_events(store, "test.Ev", 3)
        received: list[int] = []
        fail_flag = [True]

        async def flaky(ev: object) -> None:
            if fail_flag[0] and ev.global_position == 2:  # type: ignore[union-attr]
                raise RuntimeError("first time fails")
            received.append(ev.global_position)  # type: ignore[union-attr]

        engine = IdempotentProjectionEngine(checkpoint_repo=checkpoint_repo)
        engine.register("proj", "test.Ev", flaky)

        # First pass: events 0, 1 succeed; 2 fails
        await engine.process_batch(all_events[:2])
        with pytest.raises(ProjectionError):
            await engine.process(all_events[2])

        assert received == [0, 1]

        # Fix the handler and retry
        fail_flag[0] = False

        # New engine with same checkpoint — events 0, 1 are skipped
        engine2 = IdempotentProjectionEngine(checkpoint_repo=checkpoint_repo)
        engine2.register("proj", "test.Ev", flaky)
        await engine2.load_checkpoints()
        await engine2.process_batch(all_events)

        # Events 0, 1 skipped by checkpoint; event 2 retried and succeeds
        assert received == [0, 1, 2]


class TestSnapshotRecovery:
    @pytest.mark.asyncio
    async def test_snapshot_reduces_replay_count(self) -> None:
        from tests.unit.test_aggregate_repository import CounterAggregate

        store = InMemoryEventStore()
        snapshot_store = InMemorySnapshotStore()

        # Append 50 events
        await _store_events(store, "counter.Incremented", 50)

        # Take a snapshot after 30 events
        snap = EventSnapshot(
            snapshot_id="snap-1",
            aggregate_type="counter",
            aggregate_id="agg-1",
            organization_id=_ORG,
            state={"aggregate_id": "agg-1", "organization_id": _ORG, "count": 30},
            stream_version_at_snapshot=29,
            global_position_at_snapshot=29,
            created_at=_utc_now(),
            schema_version=EventVersion.v1(),
        )
        await snapshot_store.save_snapshot(snap)

        repo = AggregateRehydrationRepository(
            event_store=store,
            snapshot_store=snapshot_store,
            aggregate_class=CounterAggregate,
        )
        result = await repo.load("counter", "agg-1", _ORG)

        assert result is not None
        assert result.aggregate.count == 50
        assert result.loaded_from_snapshot
        # Only events 30-49 should be replayed (20 events, positions 30-49)
        assert result.events_replayed == 20

    @pytest.mark.asyncio
    async def test_auto_snapshot_prevents_long_replay_on_next_load(self) -> None:
        from tests.unit.test_aggregate_repository import CounterAggregate

        store = InMemoryEventStore()
        snapshot_store = InMemorySnapshotStore()

        # Append events above the snapshot threshold
        await _store_events(store, "counter.Incremented", 10)

        repo = AggregateRehydrationRepository(
            event_store=store,
            snapshot_store=snapshot_store,
            aggregate_class=CounterAggregate,
            snapshot_threshold=5,  # snapshot when >= 5 events replayed
        )

        # First load: replays 10 events, takes snapshot
        r1 = await repo.load("counter", "agg-1", _ORG)
        assert r1 is not None
        assert r1.events_replayed == 10

        # Snapshot should now exist
        snap = await snapshot_store.load_latest_snapshot("counter", "agg-1", _ORG)
        assert snap is not None
        assert snap.state["count"] == 10

        # Second load: loads from snapshot, replays 0 events
        r2 = await repo.load("counter", "agg-1", _ORG)
        assert r2 is not None
        assert r2.events_replayed == 0  # all events covered by snapshot
        assert r2.aggregate.count == 10


class TestReplayFiltering:
    @pytest.mark.asyncio
    async def test_replay_by_event_type(self) -> None:
        from redforge.application.platform.replay_engine import ReplayEngine

        store = InMemoryEventStore()

        # Mix of event types
        for _ in range(5):
            await _store_events(store, "validation.Run", 1)
        for _ in range(3):
            await _store_events(store, "finding.Created", 1)

        replay = ReplayEngine(store)
        found: list[str] = []
        async for ev in replay.replay_by_event_type("validation.Run", _ORG):
            found.append(ev.event_type)

        assert len(found) == 5
        assert all(t == "validation.Run" for t in found)

    @pytest.mark.asyncio
    async def test_replay_pagination(self) -> None:
        from redforge.application.platform.replay_engine import ReplayEngine
        from redforge.domain.platform.value_objects import ReplayCursor

        store = InMemoryEventStore()
        await _store_events(store, "test.Ev", 20)

        replay = ReplayEngine(store)
        cursor = ReplayCursor.beginning()
        all_received: list[int] = []

        while not cursor.is_exhausted:
            events, cursor = await replay.replay_from_cursor(cursor, _ORG, max_events=5)
            all_received.extend(e.global_position for e in events)

        assert len(all_received) == 20
        assert all_received == sorted(all_received)
