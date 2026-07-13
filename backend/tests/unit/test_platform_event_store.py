"""Unit tests for InMemoryEventStore — Sprint 24."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from redforge.application.platform.event_store import InMemoryEventStore, InMemorySnapshotStore
from redforge.domain.platform.events import EventBatch, EventEnvelope, EventSnapshot, make_envelope
from redforge.domain.platform.exceptions import (
    DuplicateEventError,
    MultiTenantViolationError,
    OptimisticConcurrencyError,
    StreamNotFoundError,
)
from redforge.domain.platform.value_objects import ReplayCursor

_ORG_A = "01KX3FWDMBVJTKGWNE273CN46A"
_ORG_B = "01KX3FWDMBVJTKGWNE273CN46B"
_NOW = datetime.now(UTC)


def _make_env(
    stream_id: str,
    event_type: str = "test.TestEvent",
    org: str = _ORG_A,
    aggregate_id: str = "agg-1",
) -> EventEnvelope:
    return make_envelope(
        payload={"x": 1},
        event_type=event_type,
        aggregate_type=event_type.split(".")[0],
        aggregate_id=aggregate_id,
        stream_id=stream_id,
        organization_id=org,
    )


def _batch(stream_id: str, *envs: EventEnvelope, org: str = _ORG_A) -> EventBatch:
    return EventBatch(stream_id=stream_id, organization_id=org, events=tuple(envs))


@pytest.fixture
def store() -> InMemoryEventStore:
    return InMemoryEventStore()


class TestAppend:
    @pytest.mark.asyncio
    async def test_single_event_append(self, store: InMemoryEventStore) -> None:
        ev = _make_env("campaign:a")
        stored = await store.append(_batch("campaign:a", ev))
        assert len(stored) == 1
        assert stored[0].stream_position == 0
        assert stored[0].global_position == 0

    @pytest.mark.asyncio
    async def test_sequential_positions(self, store: InMemoryEventStore) -> None:
        ev1 = _make_env("campaign:a")
        ev2 = _make_env("campaign:a")
        r1 = await store.append(_batch("campaign:a", ev1))
        r2 = await store.append(_batch("campaign:a", ev2))
        assert r1[0].stream_position == 0
        assert r2[0].stream_position == 1
        assert r1[0].global_position == 0
        assert r2[0].global_position == 1

    @pytest.mark.asyncio
    async def test_global_position_across_streams(self, store: InMemoryEventStore) -> None:
        a = _make_env("stream:a")
        b = _make_env("stream:b")
        ra = await store.append(_batch("stream:a", a))
        rb = await store.append(_batch("stream:b", b))
        assert ra[0].global_position == 0
        assert rb[0].global_position == 1

    @pytest.mark.asyncio
    async def test_duplicate_event_id_raises(self, store: InMemoryEventStore) -> None:
        ev = _make_env("campaign:a")
        await store.append(_batch("campaign:a", ev))
        with pytest.raises(DuplicateEventError):
            await store.append(_batch("campaign:a", ev))

    @pytest.mark.asyncio
    async def test_optimistic_concurrency_check(self, store: InMemoryEventStore) -> None:
        ev1 = _make_env("stream:x")
        await store.append(_batch("stream:x", ev1))
        ev2 = _make_env("stream:x")
        with pytest.raises(OptimisticConcurrencyError):
            await store.append(
                EventBatch(
                    stream_id="stream:x",
                    organization_id=_ORG_A,
                    events=(ev2,),
                    expected_stream_version=999,
                )
            )

    @pytest.mark.asyncio
    async def test_expected_version_none_skips_check(self, store: InMemoryEventStore) -> None:
        ev1 = _make_env("stream:y")
        ev2 = _make_env("stream:y")
        await store.append(_batch("stream:y", ev1))
        stored = await store.append(_batch("stream:y", ev2))
        assert len(stored) == 1

    @pytest.mark.asyncio
    async def test_recorded_at_set_by_store(self, store: InMemoryEventStore) -> None:
        ev = _make_env("s:a")
        stored = await store.append(_batch("s:a", ev))
        assert stored[0].recorded_at is not None


class TestReadStream:
    @pytest.mark.asyncio
    async def test_read_stream_returns_in_order(self, store: InMemoryEventStore) -> None:
        for _ in range(5):
            await store.append(_batch("s:a", _make_env("s:a")))
        events = await store.read_stream("s:a", _ORG_A)
        positions = [e.stream_position for e in events]
        assert positions == sorted(positions)

    @pytest.mark.asyncio
    async def test_read_stream_not_found(self, store: InMemoryEventStore) -> None:
        with pytest.raises(StreamNotFoundError):
            await store.read_stream("nonexistent", _ORG_A)

    @pytest.mark.asyncio
    async def test_read_stream_from_position(self, store: InMemoryEventStore) -> None:
        for _ in range(5):
            await store.append(_batch("s:b", _make_env("s:b")))
        events = await store.read_stream("s:b", _ORG_A, from_position=3)
        assert all(e.stream_position >= 3 for e in events)

    @pytest.mark.asyncio
    async def test_read_stream_max_count(self, store: InMemoryEventStore) -> None:
        for _ in range(10):
            await store.append(_batch("s:c", _make_env("s:c")))
        events = await store.read_stream("s:c", _ORG_A, max_count=3)
        assert len(events) == 3

    @pytest.mark.asyncio
    async def test_multi_tenant_isolation(self, store: InMemoryEventStore) -> None:
        ev = _make_env("s:a", org=_ORG_B)
        await store.append(_batch("s:a", ev, org=_ORG_B))
        with pytest.raises(MultiTenantViolationError):
            await store.read_stream("s:a", _ORG_A)


class TestReadAll:
    @pytest.mark.asyncio
    async def test_read_all_scoped_to_org(self, store: InMemoryEventStore) -> None:
        ev_a = _make_env("s:a", org=_ORG_A)
        ev_b = _make_env("s:b", org=_ORG_B)
        await store.append(_batch("s:a", ev_a, org=_ORG_A))
        await store.append(_batch("s:b", ev_b, org=_ORG_B))
        events_a = await store.read_all(_ORG_A)
        events_b = await store.read_all(_ORG_B)
        assert len(events_a) == 1
        assert len(events_b) == 1
        assert all(e.organization_id == _ORG_A for e in events_a)

    @pytest.mark.asyncio
    async def test_read_all_from_position(self, store: InMemoryEventStore) -> None:
        for _ in range(10):
            await store.append(_batch("s:a", _make_env("s:a")))
        events = await store.read_all(_ORG_A, from_global_position=5)
        assert all(e.global_position >= 5 for e in events)


class TestCorrelationAndEventType:
    @pytest.mark.asyncio
    async def test_read_by_correlation_id(self, store: InMemoryEventStore) -> None:
        ev = make_envelope(
            payload={},
            event_type="campaign.Created",
            aggregate_type="Campaign",
            aggregate_id="c1",
            stream_id="campaign:c1",
            organization_id=_ORG_A,
            correlation_id="corr-xyz",
        )
        await store.append(_batch("campaign:c1", ev))
        results = await store.read_by_correlation_id("corr-xyz", _ORG_A)
        assert len(results) == 1
        assert results[0].correlation_id == "corr-xyz"

    @pytest.mark.asyncio
    async def test_correlation_scoped_to_org(self, store: InMemoryEventStore) -> None:
        ev_a = make_envelope(
            payload={}, event_type="t.T", aggregate_type="T", aggregate_id="a",
            stream_id="t:a", organization_id=_ORG_A, correlation_id="shared-corr",
        )
        ev_b = make_envelope(
            payload={}, event_type="t.T", aggregate_type="T", aggregate_id="b",
            stream_id="t:b", organization_id=_ORG_B, correlation_id="shared-corr",
        )
        await store.append(_batch("t:a", ev_a, org=_ORG_A))
        await store.append(_batch("t:b", ev_b, org=_ORG_B))
        results_a = await store.read_by_correlation_id("shared-corr", _ORG_A)
        results_b = await store.read_by_correlation_id("shared-corr", _ORG_B)
        assert len(results_a) == 1
        assert len(results_b) == 1

    @pytest.mark.asyncio
    async def test_read_by_event_type(self, store: InMemoryEventStore) -> None:
        for _ in range(3):
            await store.append(_batch("s:a", _make_env("s:a", event_type="campaign.Created")))
        for _ in range(2):
            await store.append(_batch("s:a", _make_env("s:a", event_type="campaign.Started")))
        results = await store.read_by_event_type("campaign.Created", _ORG_A)
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_read_by_time_range(self, store: InMemoryEventStore) -> None:
        past = _NOW - timedelta(hours=2)
        future = _NOW + timedelta(hours=2)
        ev = make_envelope(
            payload={}, event_type="t.T", aggregate_type="T", aggregate_id="a",
            stream_id="t:a", organization_id=_ORG_A, occurred_at=_NOW,
        )
        await store.append(_batch("t:a", ev))
        results = await store.read_by_time_range(_ORG_A, past, future)
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_time_range_excludes_out_of_range(self, store: InMemoryEventStore) -> None:
        past = _NOW - timedelta(hours=5)
        cutoff = _NOW - timedelta(hours=3)
        ev = make_envelope(
            payload={}, event_type="t.T", aggregate_type="T", aggregate_id="a",
            stream_id="t:a", organization_id=_ORG_A, occurred_at=past,
        )
        await store.append(_batch("t:a", ev))
        results = await store.read_by_time_range(_ORG_A, cutoff, _NOW)
        assert len(results) == 0


class TestCursorReplay:
    @pytest.mark.asyncio
    async def test_cursor_replay_paginates(self, store: InMemoryEventStore) -> None:
        for _ in range(10):
            await store.append(_batch("s:a", _make_env("s:a")))
        cursor = ReplayCursor.beginning()
        events, next_cursor = await store.iter_from_cursor(cursor, _ORG_A, max_events=5)
        assert len(events) == 5
        assert not next_cursor.is_exhausted

        events2, cursor2 = await store.iter_from_cursor(next_cursor, _ORG_A, max_events=5)
        assert len(events2) == 5
        _, final = await store.iter_from_cursor(cursor2, _ORG_A, max_events=5)
        assert final.is_exhausted

    @pytest.mark.asyncio
    async def test_empty_store_exhausts_cursor(self, store: InMemoryEventStore) -> None:
        cursor = ReplayCursor.beginning()
        events, next_cursor = await store.iter_from_cursor(cursor, _ORG_A)
        assert events == []
        assert next_cursor.is_exhausted


class TestStreamMeta:
    @pytest.mark.asyncio
    async def test_stream_version(self, store: InMemoryEventStore) -> None:
        assert await store.stream_version("no-stream", _ORG_A) == -1
        await store.append(_batch("s:a", _make_env("s:a")))
        assert await store.stream_version("s:a", _ORG_A) == 0
        await store.append(_batch("s:a", _make_env("s:a")))
        assert await store.stream_version("s:a", _ORG_A) == 1

    @pytest.mark.asyncio
    async def test_event_count(self, store: InMemoryEventStore) -> None:
        assert await store.event_count(_ORG_A) == 0
        await store.append(_batch("s:a", _make_env("s:a")))
        await store.append(_batch("s:b", _make_env("s:b")))
        assert await store.event_count(_ORG_A) == 2

    @pytest.mark.asyncio
    async def test_stream_ids(self, store: InMemoryEventStore) -> None:
        await store.append(_batch("s:a", _make_env("s:a")))
        await store.append(_batch("s:b", _make_env("s:b")))
        ids = await store.stream_ids(_ORG_A)
        assert set(ids) == {"s:a", "s:b"}


# ── InMemorySnapshotStore ─────────────────────────────────────────────────

class TestInMemorySnapshotStore:
    def _snap(self, pos: int) -> EventSnapshot:
        return EventSnapshot(
            snapshot_id=f"snap-{pos}",
            aggregate_type="Campaign",
            aggregate_id="agg-1",
            organization_id=_ORG_A,
            state={"pos": pos},
            stream_version_at_snapshot=pos,
            global_position_at_snapshot=pos,
            created_at=_NOW,
        )

    @pytest.mark.asyncio
    async def test_save_and_load_latest(self) -> None:
        s = InMemorySnapshotStore()
        snap = self._snap(100)
        await s.save_snapshot(snap)
        loaded = await s.load_latest_snapshot("Campaign", "agg-1", _ORG_A)
        assert loaded is not None
        assert loaded.global_position_at_snapshot == 100

    @pytest.mark.asyncio
    async def test_newer_replaces_older(self) -> None:
        s = InMemorySnapshotStore()
        await s.save_snapshot(self._snap(50))
        await s.save_snapshot(self._snap(200))
        loaded = await s.load_latest_snapshot("Campaign", "agg-1", _ORG_A)
        assert loaded is not None
        assert loaded.global_position_at_snapshot == 200

    @pytest.mark.asyncio
    async def test_missing_returns_none(self) -> None:
        s = InMemorySnapshotStore()
        result = await s.load_latest_snapshot("Campaign", "no-agg", _ORG_A)
        assert result is None
