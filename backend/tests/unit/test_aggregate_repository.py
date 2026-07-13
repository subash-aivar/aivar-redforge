"""Unit tests for AggregateRehydrationRepository — Sprint 25."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from redforge.application.platform.aggregate_repository import (
    AggregateRehydrationRepository,
    RehydrationResult,
)
from redforge.application.platform.event_store import InMemoryEventStore, InMemorySnapshotStore
from redforge.domain.platform.events import EventBatch, EventEnvelope, EventSnapshot, make_envelope
from redforge.domain.platform.value_objects import EventVersion

_ORG = "01KX3FWDMBVJTKGWNE273CN46A"


# ── Simple test aggregate ──────────────────────────────────────────────────


class CounterAggregate:
    """Minimal rehydratable aggregate for tests."""

    aggregate_type = "counter"

    def __init__(
        self,
        aggregate_id: str,
        organization_id: str,
        count: int = 0,
        stream_version: int = -1,
    ) -> None:
        self.aggregate_id = aggregate_id
        self.organization_id = organization_id
        self.count = count
        self._stream_version = stream_version

    @classmethod
    def initial_state(cls, aggregate_id: str, organization_id: str) -> CounterAggregate:
        return cls(aggregate_id=aggregate_id, organization_id=organization_id)

    @classmethod
    def from_snapshot(
        cls, state: dict[str, Any], version: int
    ) -> CounterAggregate:
        obj = cls(
            aggregate_id=state["aggregate_id"],
            organization_id=state["organization_id"],
            count=state["count"],
            stream_version=version,
        )
        return obj

    def apply_event(self, envelope: EventEnvelope) -> None:
        if envelope.event_type == "counter.Incremented":
            self.count += 1
        elif envelope.event_type == "counter.Decremented":
            self.count -= 1
        self._stream_version = envelope.stream_position

    def to_snapshot_state(self) -> dict[str, Any]:
        return {
            "aggregate_id": self.aggregate_id,
            "organization_id": self.organization_id,
            "count": self.count,
        }

    @property
    def stream_version(self) -> int:
        return self._stream_version


# ── Helpers ────────────────────────────────────────────────────────────────


async def _append(store: InMemoryEventStore, event_type: str, agg_id: str = "c1") -> None:
    env = make_envelope(
        payload={},
        event_type=event_type,
        aggregate_type="counter",
        aggregate_id=agg_id,
        stream_id=f"counter:{agg_id}",
        organization_id=_ORG,
    )
    await store.append(EventBatch(
        stream_id=f"counter:{agg_id}",
        organization_id=_ORG,
        events=(env,),
    ))


# ── Tests ──────────────────────────────────────────────────────────────────


class TestAggregateRehydrationRepository:
    @pytest.mark.asyncio
    async def test_returns_none_for_nonexistent_aggregate(self) -> None:
        store = InMemoryEventStore()
        snapshots = InMemorySnapshotStore()
        repo = AggregateRehydrationRepository(
            event_store=store,
            snapshot_store=snapshots,
            aggregate_class=CounterAggregate,
        )
        result = await repo.load("counter", "nonexistent", _ORG)
        assert result is None

    @pytest.mark.asyncio
    async def test_rehydrates_from_events(self) -> None:
        store = InMemoryEventStore()
        snapshots = InMemorySnapshotStore()

        for _ in range(3):
            await _append(store, "counter.Incremented")

        repo = AggregateRehydrationRepository(
            event_store=store,
            snapshot_store=snapshots,
            aggregate_class=CounterAggregate,
        )
        result = await repo.load("counter", "c1", _ORG)

        assert result is not None
        assert isinstance(result, RehydrationResult)
        assert result.aggregate.count == 3
        assert result.events_replayed == 3
        assert not result.loaded_from_snapshot

    @pytest.mark.asyncio
    async def test_rehydrates_from_snapshot_plus_events(self) -> None:
        store = InMemoryEventStore()
        snapshots = InMemorySnapshotStore()

        # Simulate a snapshot at stream_version=4 (count=5)
        snapshot = EventSnapshot(
            snapshot_id="snap-1",
            aggregate_type="counter",
            aggregate_id="c1",
            organization_id=_ORG,
            state={"aggregate_id": "c1", "organization_id": _ORG, "count": 5},
            stream_version_at_snapshot=4,
            global_position_at_snapshot=4,
            created_at=datetime.now(UTC),
            schema_version=EventVersion.v1(),
        )
        await snapshots.save_snapshot(snapshot)

        # Append all 7 events to the store (positions 0-6).
        # The snapshot covers positions 0-4 (stream_version=4),
        # so rehydration will only replay events from stream_position >= 5.
        for _ in range(5):
            env = make_envelope(
                payload={},
                event_type="counter.Incremented",
                aggregate_type="counter",
                aggregate_id="c1",
                stream_id="counter:c1",
                organization_id=_ORG,
            )
            await store.append(EventBatch(
                stream_id="counter:c1",
                organization_id=_ORG,
                events=(env,),
            ))

        # Now append 2 more increments AFTER the snapshot position
        for _i in range(2):
            env = make_envelope(
                payload={},
                event_type="counter.Incremented",
                aggregate_type="counter",
                aggregate_id="c1",
                stream_id="counter:c1",
                organization_id=_ORG,
            )
            await store.append(EventBatch(
                stream_id="counter:c1",
                organization_id=_ORG,
                events=(env,),
            ))

        repo = AggregateRehydrationRepository(
            event_store=store,
            snapshot_store=snapshots,
            aggregate_class=CounterAggregate,
        )
        result = await repo.load("counter", "c1", _ORG)

        assert result is not None
        assert result.aggregate.count == 7  # 5 from snapshot + 2 replayed
        assert result.loaded_from_snapshot
        assert result.snapshot_version == 4

    @pytest.mark.asyncio
    async def test_snapshot_taken_when_threshold_exceeded(self) -> None:
        store = InMemoryEventStore()
        snapshots = InMemorySnapshotStore()

        # Append 3 events
        for _ in range(3):
            await _append(store, "counter.Incremented")

        repo = AggregateRehydrationRepository(
            event_store=store,
            snapshot_store=snapshots,
            aggregate_class=CounterAggregate,
            snapshot_threshold=2,  # snapshot when >= 2 events replayed
        )
        await repo.load("counter", "c1", _ORG)

        # Snapshot should have been saved
        snap = await snapshots.load_latest_snapshot("counter", "c1", _ORG)
        assert snap is not None
        assert snap.state["count"] == 3

    @pytest.mark.asyncio
    async def test_decrement_event_decreases_count(self) -> None:
        store = InMemoryEventStore()
        snapshots = InMemorySnapshotStore()

        await _append(store, "counter.Incremented")
        await _append(store, "counter.Incremented")
        await _append(store, "counter.Decremented")

        repo = AggregateRehydrationRepository(
            event_store=store,
            snapshot_store=snapshots,
            aggregate_class=CounterAggregate,
        )
        result = await repo.load("counter", "c1", _ORG)

        assert result is not None
        assert result.aggregate.count == 1
        assert result.events_replayed == 3

    @pytest.mark.asyncio
    async def test_different_aggregates_isolated(self) -> None:
        store = InMemoryEventStore()
        snapshots = InMemorySnapshotStore()

        await _append(store, "counter.Incremented", agg_id="c1")
        await _append(store, "counter.Incremented", agg_id="c1")
        await _append(store, "counter.Incremented", agg_id="c2")

        repo = AggregateRehydrationRepository(
            event_store=store,
            snapshot_store=snapshots,
            aggregate_class=CounterAggregate,
        )
        r1 = await repo.load("counter", "c1", _ORG)
        r2 = await repo.load("counter", "c2", _ORG)

        assert r1 is not None and r1.aggregate.count == 2
        assert r2 is not None and r2.aggregate.count == 1
