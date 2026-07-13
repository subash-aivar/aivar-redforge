"""Unit tests for IdempotentProjectionEngine — Sprint 25.

Tests:
- Exactly-once semantics: duplicate event_id is a no-op for a projection
- Checkpoint recovery: events at position <= checkpoint are skipped on restart
- Per-projection isolation: projection A skipping doesn't affect projection B
- Counter correctness: counts don't inflate on re-delivery
- Handler errors are re-raised and do not advance checkpoint
- Batch processing maintains order
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.application.platform.idempotent_projection_engine import (
    IdempotentProjectionEngine,
)
from redforge.application.platform.projection_engine import (
    InMemoryCheckpointRepository,
)
from redforge.domain.platform.events import make_envelope
from redforge.domain.platform.exceptions import ProjectionError
from redforge.domain.platform.value_objects import ProjectionCheckpoint, ProjectionState

_ORG = "01KX3FWDMBVJTKGWNE273CN46A"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _env(
    stream_id: str = "test:agg",
    event_type: str = "test.Event",
    org: str = _ORG,
    aggregate_id: str = "agg-1",
) -> object:
    return make_envelope(
        payload={"x": 1},
        event_type=event_type,
        aggregate_type="test",
        aggregate_id=aggregate_id,
        stream_id=stream_id,
        organization_id=org,
    )


async def _stored(env: object, pos: int, stream_pos: int = 0) -> object:
    """Simulate an envelope that has been stored (has real positions)."""
    import dataclasses
    return dataclasses.replace(env, global_position=pos, stream_position=stream_pos)


@pytest.fixture
def checkpoint_repo() -> InMemoryCheckpointRepository:
    return InMemoryCheckpointRepository()


@pytest.fixture
def engine(checkpoint_repo: InMemoryCheckpointRepository) -> IdempotentProjectionEngine:
    return IdempotentProjectionEngine(checkpoint_repo=checkpoint_repo)


class TestExactlyOnce:
    @pytest.mark.asyncio
    async def test_single_event_processed_once(
        self, engine: IdempotentProjectionEngine
    ) -> None:
        calls: list[str] = []

        async def handler(ev: object) -> None:
            calls.append(ev.event_id)  # type: ignore[union-attr]

        engine.register("proj_a", "test.Event", handler)
        env = _env()
        stored_env = await _stored(env, pos=5)
        await engine.process(stored_env)
        assert len(calls) == 1

    @pytest.mark.asyncio
    async def test_duplicate_event_id_skipped(
        self, engine: IdempotentProjectionEngine
    ) -> None:
        calls: list[str] = []

        async def handler(ev: object) -> None:
            calls.append("called")

        engine.register("proj_a", "test.Event", handler)
        env = _env()
        stored_env = await _stored(env, pos=5)

        await engine.process(stored_env)
        # Deliver the same event again (same event_id)
        await engine.process(stored_env)

        assert len(calls) == 1  # only processed once
        assert engine.events_skipped == 1

    @pytest.mark.asyncio
    async def test_per_projection_isolation(
        self, engine: IdempotentProjectionEngine
    ) -> None:
        calls_a: list[str] = []
        calls_b: list[str] = []

        async def handler_a(ev: object) -> None:
            calls_a.append("a")

        async def handler_b(ev: object) -> None:
            calls_b.append("b")

        engine.register("proj_a", "test.Event", handler_a)
        engine.register("proj_b", "test.Event", handler_b)

        env = _env()
        stored_env = await _stored(env, pos=5)

        # First delivery: both should process
        await engine.process(stored_env)
        assert len(calls_a) == 1
        assert len(calls_b) == 1

        # Second delivery: both should skip
        await engine.process(stored_env)
        assert len(calls_a) == 1
        assert len(calls_b) == 1


class TestCheckpointRecovery:
    @pytest.mark.asyncio
    async def test_checkpoint_is_saved_after_processing(
        self,
        engine: IdempotentProjectionEngine,
        checkpoint_repo: InMemoryCheckpointRepository,
    ) -> None:
        async def handler(ev: object) -> None:
            pass

        engine.register("proj_a", "test.Event", handler)
        env = await _stored(_env(), pos=10)
        await engine.process(env)

        cp = await checkpoint_repo.load("proj_a")
        assert cp is not None
        assert cp.last_global_position == 10

    @pytest.mark.asyncio
    async def test_events_before_checkpoint_skipped_on_restart(
        self, checkpoint_repo: InMemoryCheckpointRepository
    ) -> None:
        # Simulate a prior checkpoint at position 99
        await checkpoint_repo.save(ProjectionCheckpoint(
            projection_id="proj_a",
            projection_name="proj_a",
            last_global_position=99,
            last_processed_at=_utc_now(),
            state=ProjectionState.LIVE,
        ))

        # New engine instance loads checkpoint
        engine = IdempotentProjectionEngine(checkpoint_repo=checkpoint_repo)
        calls: list[int] = []

        async def handler(ev: object) -> None:
            calls.append(ev.global_position)  # type: ignore[union-attr]

        engine.register("proj_a", "test.Event", handler)
        await engine.load_checkpoints()

        # Deliver events at positions 50, 99, 100, 101
        for pos in [50, 99, 100, 101]:
            env = await _stored(_env(), pos=pos)
            await engine.process(env)

        # Only positions 100 and 101 should be processed (after checkpoint)
        assert calls == [100, 101]

    @pytest.mark.asyncio
    async def test_checkpoint_advances_monotonically(
        self,
        engine: IdempotentProjectionEngine,
        checkpoint_repo: InMemoryCheckpointRepository,
    ) -> None:
        async def handler(ev: object) -> None:
            pass

        engine.register("proj_a", "test.Event", handler)

        for pos in [1, 2, 3, 4, 5]:
            env = await _stored(_env(), pos=pos)
            await engine.process(env)

        cp = await checkpoint_repo.load("proj_a")
        assert cp is not None
        assert cp.last_global_position == 5


class TestHandlerErrors:
    @pytest.mark.asyncio
    async def test_handler_error_raises_projection_error(
        self, engine: IdempotentProjectionEngine
    ) -> None:
        async def bad_handler(ev: object) -> None:
            raise RuntimeError("boom")

        engine.register("proj_a", "test.Event", bad_handler)
        env = await _stored(_env(), pos=1)

        with pytest.raises(ProjectionError):
            await engine.process(env)

    @pytest.mark.asyncio
    async def test_failed_event_not_checkpointed(
        self,
        engine: IdempotentProjectionEngine,
        checkpoint_repo: InMemoryCheckpointRepository,
    ) -> None:
        async def bad_handler(ev: object) -> None:
            raise RuntimeError("boom")

        engine.register("proj_a", "test.Event", bad_handler)
        env = await _stored(_env(), pos=1)

        with pytest.raises(ProjectionError):
            await engine.process(env)

        cp = await checkpoint_repo.load("proj_a")
        assert cp is None  # no checkpoint saved on failure


class TestBatchProcessing:
    @pytest.mark.asyncio
    async def test_batch_order_preserved(
        self, engine: IdempotentProjectionEngine
    ) -> None:
        received: list[int] = []

        async def handler(ev: object) -> None:
            received.append(ev.global_position)  # type: ignore[union-attr]

        engine.register("proj_a", "test.Event", handler)

        envs = [await _stored(_env(), pos=i) for i in range(10)]
        await engine.process_batch(envs)

        assert received == list(range(10))

    @pytest.mark.asyncio
    async def test_batch_with_duplicates_skips_correctly(
        self, engine: IdempotentProjectionEngine
    ) -> None:
        received: list[int] = []

        async def handler(ev: object) -> None:
            received.append(ev.global_position)  # type: ignore[union-attr]

        engine.register("proj_a", "test.Event", handler)

        env0 = await _stored(_env(), pos=0)
        env1 = await _stored(_env(), pos=1)

        # First pass
        await engine.process_batch([env0, env1])
        # Second pass of same events
        await engine.process_batch([env0, env1])

        assert received == [0, 1]  # each processed exactly once

    @pytest.mark.asyncio
    async def test_registered_projections_listed(
        self, engine: IdempotentProjectionEngine
    ) -> None:
        async def h(ev: object) -> None:
            pass

        engine.register("proj_alpha", "test.A", h)
        engine.register("proj_beta", "test.A", h)

        names = engine.registered_projections()
        assert "proj_alpha" in names
        assert "proj_beta" in names
