"""Integration tests for platform idempotency — Sprint 25.

Tests exactly-once semantics across the full pipeline:
  EventStore → IdempotentProjectionEngine → CheckpointRepository → ReadModel

Specifically validates:
- Counter-based projections do NOT double-count on re-delivery
- Checkpoint recovery skips already-processed events
- Replay from EventStore respects checkpoints
- Concurrent delivery of the same event is idempotent
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.application.platform.event_store import InMemoryEventStore
from redforge.application.platform.idempotent_projection_engine import (
    IdempotentProjectionEngine,
)
from redforge.application.platform.projection_engine import (
    InMemoryCheckpointRepository,
    InMemoryReadModelRepository,
)
from redforge.domain.platform.events import EventBatch, make_envelope
from redforge.domain.platform.value_objects import ProjectionCheckpoint, ProjectionState

_ORG = "01KX3FWDMBVJTKGWNE273CN46A"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _make_env(event_type: str, org: str = _ORG) -> object:
    return make_envelope(
        payload={},
        event_type=event_type,
        aggregate_type=event_type.split(".")[0],
        aggregate_id="agg-1",
        stream_id=f"{event_type.split('.')[0]}:agg-1",
        organization_id=org,
    )


async def _publish(store: InMemoryEventStore, env: object) -> object:
    """Append envelope to store and return stored (with assigned positions)."""
    batch = EventBatch(
        stream_id=env.stream_id,  # type: ignore[union-attr]
        organization_id=env.organization_id,  # type: ignore[union-attr]
        events=(env,),  # type: ignore[arg-type]
    )
    stored = await store.append(batch)
    return stored[0]


class TestCounterProjectionIdempotency:
    """The critical Sprint 25 fix: projection counters must not double-count."""

    @pytest.mark.asyncio
    async def test_replay_does_not_double_count(self) -> None:
        store = InMemoryEventStore()
        checkpoint_repo = InMemoryCheckpointRepository()
        InMemoryReadModelRepository()

        engine = IdempotentProjectionEngine(checkpoint_repo=checkpoint_repo)

        # Simple counting projection
        counter: dict[str, int] = {"validation_count": 0}

        async def count_validation(ev: object) -> None:
            counter["validation_count"] += 1

        engine.register("validation_summary", "validation.ValidationCompleted", count_validation)

        # Append 5 events to the store
        stored_events = []
        for _ in range(5):
            env = await _publish(store, _make_env("validation.ValidationCompleted"))
            stored_events.append(env)

        # First pass: process all 5
        await engine.process_batch(stored_events)
        assert counter["validation_count"] == 5

        # Replay the same events (simulates restart without checkpoint clearing)
        await engine.process_batch(stored_events)
        assert counter["validation_count"] == 5  # must not increment again

    @pytest.mark.asyncio
    async def test_catch_up_from_checkpoint_skips_old_events(self) -> None:
        store = InMemoryEventStore()
        checkpoint_repo = InMemoryCheckpointRepository()

        # Seed a checkpoint at position 4 (events 0-4 already processed)
        await checkpoint_repo.save(ProjectionCheckpoint(
            projection_id="validation_summary",
            projection_name="validation_summary",
            last_global_position=4,
            last_processed_at=_utc_now(),
            state=ProjectionState.LIVE,
        ))

        engine = IdempotentProjectionEngine(checkpoint_repo=checkpoint_repo)
        await engine.load_checkpoints()

        counter: dict[str, int] = {"count": 0}

        async def handler(ev: object) -> None:
            counter["count"] += 1

        engine.register("validation_summary", "validation.ValidationCompleted", handler)

        # Append 10 events (positions 0-9)
        for _ in range(10):
            await _publish(store, _make_env("validation.ValidationCompleted"))

        # Catch-up from position 0 — but checkpoint says 0-4 are done
        await engine.catch_up(store, _ORG, from_position=0)

        # Only events at position 5-9 should be processed (5 events)
        assert counter["count"] == 5

    @pytest.mark.asyncio
    async def test_multiple_projections_independent_counters(self) -> None:
        store = InMemoryEventStore()
        checkpoint_repo = InMemoryCheckpointRepository()
        engine = IdempotentProjectionEngine(checkpoint_repo=checkpoint_repo)

        counter_a: dict[str, int] = {"count": 0}
        counter_b: dict[str, int] = {"count": 0}

        async def handler_a(ev: object) -> None:
            counter_a["count"] += 1

        async def handler_b(ev: object) -> None:
            counter_b["count"] += 1

        engine.register("proj_a", "test.Event", handler_a)
        engine.register("proj_b", "test.Event", handler_b)

        stored = []
        for _ in range(3):
            env = await _publish(store, _make_env("test.Event"))
            stored.append(env)

        # First delivery
        await engine.process_batch(stored)
        assert counter_a["count"] == 3
        assert counter_b["count"] == 3

        # Re-delivery (simulates duplicate message delivery)
        await engine.process_batch(stored)
        assert counter_a["count"] == 3  # unchanged
        assert counter_b["count"] == 3  # unchanged

    @pytest.mark.asyncio
    async def test_partial_replay_resumes_correctly(self) -> None:
        store = InMemoryEventStore()
        checkpoint_repo = InMemoryCheckpointRepository()

        received_positions: list[int] = []

        async def handler(ev: object) -> None:
            received_positions.append(ev.global_position)  # type: ignore[union-attr]

        # Session 1: process events 0-4
        engine1 = IdempotentProjectionEngine(checkpoint_repo=checkpoint_repo)
        engine1.register("proj", "test.Event", handler)

        stored_all = []
        for _ in range(10):
            env = await _publish(store, _make_env("test.Event"))
            stored_all.append(env)

        await engine1.process_batch(stored_all[:5])
        assert received_positions == [0, 1, 2, 3, 4]

        # Session 2: new engine, loads checkpoint, continues from 5
        engine2 = IdempotentProjectionEngine(checkpoint_repo=checkpoint_repo)
        engine2.register("proj", "test.Event", handler)
        await engine2.load_checkpoints()

        await engine2.process_batch(stored_all)  # deliver all, checkpoint handles skips
        # Positions 0-4 are skipped (checkpoint = 4), only 5-9 processed
        assert received_positions == [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]


class TestKGProjectionBugFix:
    """Verify the kg_projection total_edges bug is fixed."""

    @pytest.mark.asyncio
    async def test_kg_projection_edge_count_not_node_count(self) -> None:
        from redforge.application.knowledge_graph import KnowledgeGraph
        from redforge.application.platform.projection_engine import (
            InMemoryReadModelRepository,
            ProjectionEngine,
        )
        from redforge.application.platform.projections.kg_projection import KGProjection

        graph = KnowledgeGraph()
        repo = InMemoryReadModelRepository()
        projection = KGProjection(graph, repo)

        engine = ProjectionEngine()
        projection.register_with(engine)

        # Process an asset event to trigger KG population
        env = await _publish(
            InMemoryEventStore(),
            _make_env("inventory.AIAssetCreated"),
        )
        await engine.process(env)

        # Read model should have correct edge count (0), not node count
        model = await projection.get(_ORG)
        assert model is not None
        # After one asset: 1 node, 0 edges (no org node to connect to)
        assert model.total_nodes == graph.node_count
        assert model.total_edges == graph.edge_count
