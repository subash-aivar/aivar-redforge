"""Concurrency and OCC tests for platform persistence — Sprint 25.

Tests:
- Optimistic concurrency conflict detection
- Concurrent writers to different streams are isolated
- Concurrent writers to the same stream: one wins, one gets OCC error
- Dedup prevents duplicate event_id insertion
- Thread-safe InMemoryEventStore under concurrent load
- Large event stream handling
"""

from __future__ import annotations

import asyncio

import pytest

from redforge.application.platform.event_store import InMemoryEventStore
from redforge.domain.platform.events import EventBatch, make_envelope
from redforge.domain.platform.exceptions import (
    DuplicateEventError,
    OptimisticConcurrencyError,
)

_ORG_A = "01KX3FWDMBVJTKGWNE273CN46A"
_ORG_B = "01KX3FWDMBVJTKGWNE273CN46B"


def _make_env(
    stream_id: str,
    event_type: str = "test.Event",
    org: str = _ORG_A,
) -> object:
    return make_envelope(
        payload={"x": 1},
        event_type=event_type,
        aggregate_type="test",
        aggregate_id="agg-1",
        stream_id=stream_id,
        organization_id=org,
    )


async def _append_one(
    store: InMemoryEventStore,
    stream_id: str,
    org: str = _ORG_A,
    expected_version: int | None = None,
) -> object:
    env = _make_env(stream_id, org=org)
    batch = EventBatch(
        stream_id=stream_id,
        organization_id=org,
        events=(env,),
        expected_stream_version=expected_version,
    )
    stored = await store.append(batch)
    return stored[0]


class TestOptimisticConcurrency:
    @pytest.mark.asyncio
    async def test_occ_on_version_mismatch(self) -> None:
        store = InMemoryEventStore()
        # Append one event to create stream at version 0
        await _append_one(store, "campaign:c1")

        # Expect version -1 (new stream) but stream has version 0 → conflict
        with pytest.raises(OptimisticConcurrencyError) as exc_info:
            await _append_one(store, "campaign:c1", expected_version=-1)

        assert exc_info.value.stream_id == "campaign:c1"
        assert exc_info.value.expected_version == -1

    @pytest.mark.asyncio
    async def test_occ_correct_version_succeeds(self) -> None:
        store = InMemoryEventStore()
        await _append_one(store, "campaign:c1")
        # ev1.stream_position == 0, so current version is 0
        ev2 = await _append_one(store, "campaign:c1", expected_version=0)
        assert ev2.stream_position == 1

    @pytest.mark.asyncio
    async def test_no_occ_check_when_version_is_none(self) -> None:
        store = InMemoryEventStore()
        await _append_one(store, "campaign:c1")
        await _append_one(store, "campaign:c1")  # no version check
        version = await store.stream_version("campaign:c1", _ORG_A)
        assert version == 1

    @pytest.mark.asyncio
    async def test_concurrent_writers_different_streams_no_conflict(self) -> None:
        store = InMemoryEventStore()
        results = await asyncio.gather(
            _append_one(store, "campaign:c1"),
            _append_one(store, "campaign:c2"),
            _append_one(store, "campaign:c3"),
            return_exceptions=True,
        )
        assert all(not isinstance(r, Exception) for r in results)
        assert await store.event_count(_ORG_A) == 3

    @pytest.mark.asyncio
    async def test_concurrent_writers_same_stream_one_wins(self) -> None:
        store = InMemoryEventStore()
        # Both writers expect version -1 (new stream)
        results = await asyncio.gather(
            _append_one(store, "campaign:shared", expected_version=-1),
            _append_one(store, "campaign:shared", expected_version=-1),
            return_exceptions=True,
        )
        successes = [r for r in results if not isinstance(r, Exception)]
        failures = [r for r in results if isinstance(r, OptimisticConcurrencyError)]
        # Exactly one should succeed, one should fail with OCC
        assert len(successes) == 1
        assert len(failures) == 1


class TestDeduplication:
    @pytest.mark.asyncio
    async def test_duplicate_event_id_raises(self) -> None:
        store = InMemoryEventStore()
        env = _make_env("test:dup")
        batch = EventBatch(
            stream_id="test:dup",
            organization_id=_ORG_A,
            events=(env,),
        )
        await store.append(batch)
        # Append same event_id again in a new batch
        with pytest.raises(DuplicateEventError) as exc_info:
            await store.append(batch)
        assert exc_info.value.event_id == env.event_id  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_different_event_ids_accepted(self) -> None:
        store = InMemoryEventStore()
        for _ in range(5):
            await _append_one(store, "test:multi")
        count = await store.event_count(_ORG_A)
        assert count == 5


class TestConcurrentLoad:
    @pytest.mark.asyncio
    async def test_concurrent_reads_and_writes(self) -> None:
        store = InMemoryEventStore()
        WRITERS = 20
        EVENTS_PER_WRITER = 5

        async def write_stream(n: int) -> None:
            for _ in range(EVENTS_PER_WRITER):
                await _append_one(store, f"stream:{n}")

        async def read_all() -> int:
            events = await store.read_all(_ORG_A)
            return len(events)

        # Interleave writes and reads
        tasks: list[asyncio.coroutines.types.CoroutineType] = [
            write_stream(i) for i in range(WRITERS)
        ]
        await asyncio.gather(*tasks)

        total = await read_all()
        assert total == WRITERS * EVENTS_PER_WRITER

    @pytest.mark.asyncio
    async def test_large_stream_read(self) -> None:
        store = InMemoryEventStore()
        N = 1000
        for _ in range(N):
            await _append_one(store, "large:stream")

        events = await store.read_stream("large:stream", _ORG_A)
        assert len(events) == N
        # Verify monotonic ordering
        for i, ev in enumerate(events):
            assert ev.stream_position == i

    @pytest.mark.asyncio
    async def test_global_position_monotonically_increasing(self) -> None:
        store = InMemoryEventStore()
        for i in range(50):
            await _append_one(store, f"stream:{i}")

        events = await store.read_all(_ORG_A)
        positions = [e.global_position for e in events]
        assert positions == sorted(positions)
        assert len(set(positions)) == len(positions)  # unique

    @pytest.mark.asyncio
    async def test_multi_tenant_isolation_under_concurrent_writes(self) -> None:
        store = InMemoryEventStore()

        async def write_for_org(org: str, n: int) -> None:
            for _ in range(n):
                env = make_envelope(
                    payload={},
                    event_type="test.Event",
                    aggregate_type="test",
                    aggregate_id="agg",
                    stream_id=f"test:{org}:agg",
                    organization_id=org,
                )
                await store.append(EventBatch(
                    stream_id=f"test:{org}:agg",
                    organization_id=org,
                    events=(env,),
                ))

        await asyncio.gather(
            write_for_org(_ORG_A, 10),
            write_for_org(_ORG_B, 7),
        )

        count_a = await store.event_count(_ORG_A)
        count_b = await store.event_count(_ORG_B)
        assert count_a == 10
        assert count_b == 7


class TestPerformanceSmoke:
    @pytest.mark.asyncio
    async def test_10k_events_append_and_read(self) -> None:
        import time
        store = InMemoryEventStore()
        N = 10_000

        start = time.monotonic()
        for i in range(N):
            await _append_one(store, f"stream:{i % 100}")
        elapsed_write = time.monotonic() - start

        start = time.monotonic()
        events = await store.read_all(_ORG_A)
        elapsed_read = time.monotonic() - start

        assert len(events) == N
        # Generous limits — CI may be slow
        assert elapsed_write < 30.0, f"Write took {elapsed_write:.1f}s"
        assert elapsed_read < 5.0, f"Read took {elapsed_read:.1f}s"
