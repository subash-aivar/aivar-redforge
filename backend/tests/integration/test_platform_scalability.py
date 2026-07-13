"""Platform scalability tests — Sprint 24.

Tests: 1 million event simulation, concurrent publishers, multi-tenant
isolation at scale, order correctness under concurrent writes.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from redforge.application.platform.event_store import InMemoryEventStore
from redforge.application.platform.projection_engine import (
    InMemoryReadModelRepository,
    ProjectionEngine,
)
from redforge.application.platform.projections.organization_activity_projection import (
    OrganizationActivityProjection,
)
from redforge.application.platform.replay_engine import ReplayEngine
from redforge.domain.platform.events import EventBatch, EventEnvelope, make_envelope
from redforge.domain.platform.value_objects import ReplayCursor

_ORG_A = "01KX3FWDMBVJTKGWNE273CN46A"
_ORG_B = "01KX3FWDMBVJTKGWNE273CN46B"


def _make_env(stream_id: str, org: str, event_type: str = "t.T") -> EventEnvelope:
    """Build an EventEnvelope whose stream_id matches the intended batch stream."""
    return make_envelope(
        payload={},
        event_type=event_type,
        aggregate_type=event_type.split(".")[0],
        aggregate_id="agg",
        stream_id=stream_id,
        organization_id=org,
    )


async def _fill_stream(
    store: InMemoryEventStore,
    stream_id: str,
    org: str,
    count: int,
    event_type: str = "t.T",
) -> int:
    """Append `count` events to a single stream. Returns number appended."""
    envs = [_make_env(stream_id, org, event_type) for _ in range(count)]
    batch = EventBatch(stream_id=stream_id, organization_id=org, events=tuple(envs))
    stored = await store.append(batch)
    return len(stored)


class TestLargeEventStream:
    @pytest.mark.asyncio
    async def test_one_million_events_append_and_read(self) -> None:
        """Simulate 1 million events using batch appends of 10K per stream."""
        store = InMemoryEventStore()
        TOTAL = 1_000_000
        BATCH_SIZE = 10_000

        start = time.monotonic()
        for batch_num in range(TOTAL // BATCH_SIZE):
            s = f"campaign:batch-{batch_num}"
            await _fill_stream(store, s, _ORG_A, BATCH_SIZE, "campaign.Created")
        elapsed = time.monotonic() - start

        assert store.total_event_count() == TOTAL
        assert elapsed < 60, f"1M event append took {elapsed:.2f}s (limit: 60s)"

    @pytest.mark.asyncio
    async def test_one_million_events_read_via_cursor(self) -> None:
        """Read all 1M events in pages via cursor — verifies scan performance."""
        store = InMemoryEventStore()
        TOTAL = 1_000_000
        BATCH_SIZE = 10_000

        for batch_num in range(TOTAL // BATCH_SIZE):
            s = f"campaign:read-batch-{batch_num}"
            await _fill_stream(store, s, _ORG_A, BATCH_SIZE, "campaign.Created")

        start = time.monotonic()
        cursor = ReplayCursor.beginning()
        total_read = 0
        while not cursor.is_exhausted:
            events, cursor = await store.iter_from_cursor(cursor, _ORG_A, max_events=100_000)
            total_read += len(events)
        elapsed = time.monotonic() - start

        assert total_read == TOTAL
        assert elapsed < 30, f"Reading 1M events took {elapsed:.2f}s (limit: 30s)"


class TestConcurrentPublishers:
    @pytest.mark.asyncio
    async def test_concurrent_publishers_no_corruption(self) -> None:
        """Multiple concurrent publishers writing to different streams — no corruption."""
        store = InMemoryEventStore()
        NUM_PUBLISHERS = 20
        EVENTS_PER_PUBLISHER = 100

        async def publish(publisher_id: int) -> None:
            stream_id = f"publisher:{publisher_id}"
            for _i in range(EVENTS_PER_PUBLISHER):
                ev = _make_env(stream_id, _ORG_A)
                batch = EventBatch(stream_id=stream_id, organization_id=_ORG_A, events=(ev,))
                await store.append(batch)

        await asyncio.gather(*[publish(i) for i in range(NUM_PUBLISHERS)])

        assert store.total_event_count() == NUM_PUBLISHERS * EVENTS_PER_PUBLISHER

    @pytest.mark.asyncio
    async def test_concurrent_publishers_global_positions_unique(self) -> None:
        """Global positions must be unique even under concurrent writes."""
        store = InMemoryEventStore()
        NUM_PUBLISHERS = 10
        EVENTS_PER_PUBLISHER = 50

        all_stored: list[EventEnvelope] = []
        lock = asyncio.Lock()

        async def publish(publisher_id: int) -> None:
            stream_id = f"pub:{publisher_id}"
            for _ in range(EVENTS_PER_PUBLISHER):
                ev = _make_env(stream_id, _ORG_A)
                batch = EventBatch(stream_id=stream_id, organization_id=_ORG_A, events=(ev,))
                stored = await store.append(batch)
                async with lock:
                    all_stored.extend(stored)

        await asyncio.gather(*[publish(i) for i in range(NUM_PUBLISHERS)])

        positions = [e.global_position for e in all_stored]
        assert len(positions) == len(set(positions)), "Duplicate global positions detected"

    @pytest.mark.asyncio
    async def test_concurrent_publishers_multi_tenant(self) -> None:
        """Concurrent writes to two orgs — counts remain isolated."""
        store = InMemoryEventStore()
        COUNT_A = 200
        COUNT_B = 300

        async def publish_org(org: str, count: int) -> None:
            for i in range(count):
                stream_id = f"t:{org}-{i}"
                ev = _make_env(stream_id, org)
                batch = EventBatch(stream_id=stream_id, organization_id=org, events=(ev,))
                await store.append(batch)

        await asyncio.gather(
            publish_org(_ORG_A, COUNT_A),
            publish_org(_ORG_B, COUNT_B),
        )

        assert await store.event_count(_ORG_A) == COUNT_A
        assert await store.event_count(_ORG_B) == COUNT_B


class TestProjectionScalability:
    @pytest.mark.asyncio
    async def test_catch_up_100k_events(self) -> None:
        """ProjectionEngine catches up 100K events without degradation."""
        store = InMemoryEventStore()
        repo = InMemoryReadModelRepository()
        engine = ProjectionEngine()
        proj = OrganizationActivityProjection(repo)
        proj.register_with(engine)

        TOTAL = 100_000
        BATCH_SIZE = 1_000
        for batch_num in range(TOTAL // BATCH_SIZE):
            s = f"campaign:batch-{batch_num}"
            await _fill_stream(store, s, _ORG_A, BATCH_SIZE, "campaign.Created")

        start = time.monotonic()
        count = await engine.catch_up(store, _ORG_A)
        elapsed = time.monotonic() - start

        assert count == TOTAL
        model = await proj.get(_ORG_A)
        assert model is not None
        assert model.total_events == TOTAL
        assert elapsed < 30, f"Catch-up of 100K events took {elapsed:.2f}s (limit: 30s)"

    @pytest.mark.asyncio
    async def test_replay_engine_100_orgs(self) -> None:
        """Replay is correctly isolated for 100 different organisations."""
        store = InMemoryEventStore()
        engine = ReplayEngine(store)
        NUM_ORGS = 100
        EVENTS_PER_ORG = 10

        orgs = [f"01KX3FWDMBVJTKGWNE273C{i:05d}" for i in range(NUM_ORGS)]

        for org in orgs:
            s = f"t:{org}"
            await _fill_stream(store, s, org, EVENTS_PER_ORG)

        for org in orgs[:10]:  # sample check on 10 orgs
            results = await engine.collect(engine.replay_organization(org))
            assert len(results) == EVENTS_PER_ORG, (
                f"Expected {EVENTS_PER_ORG} events for org {org}, got {len(results)}"
            )


class TestEventOrdering:
    @pytest.mark.asyncio
    async def test_global_positions_monotonically_increasing(self) -> None:
        store = InMemoryEventStore()
        for i in range(50):
            s = f"stream:{i}"
            ev = _make_env(s, _ORG_A)
            batch = EventBatch(stream_id=s, organization_id=_ORG_A, events=(ev,))
            await store.append(batch)

        events = await store.read_all(_ORG_A)
        positions = [e.global_position for e in events]
        assert positions == sorted(positions)
        assert len(set(positions)) == len(positions)

    @pytest.mark.asyncio
    async def test_stream_positions_monotonic_within_stream(self) -> None:
        store = InMemoryEventStore()
        for _ in range(20):
            ev = _make_env("t:agg", _ORG_A)
            batch = EventBatch(stream_id="t:agg", organization_id=_ORG_A, events=(ev,))
            await store.append(batch)

        events = await store.read_stream("t:agg", _ORG_A)
        positions = [e.stream_position for e in events]
        assert positions == list(range(20))
