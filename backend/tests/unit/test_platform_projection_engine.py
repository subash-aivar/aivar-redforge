"""Unit tests for ProjectionEngine, EventBus, CheckpointRepo — Sprint 24."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.application.platform.event_bus import InMemoryEventBus
from redforge.application.platform.event_store import InMemoryEventStore
from redforge.application.platform.projection_engine import (
    InMemoryCheckpointRepository,
    InMemoryReadModelRepository,
    ProjectionEngine,
)
from redforge.domain.platform.events import EventBatch, EventEnvelope, make_envelope
from redforge.domain.platform.exceptions import ProjectionError
from redforge.domain.platform.value_objects import ProjectionCheckpoint, ProjectionState

_ORG = "01KX3FWDMBVJTKGWNE273CN45D"
_NOW = datetime.now(UTC)


def _env(event_type: str, agg_id: str = "a1") -> EventEnvelope:
    return make_envelope(
        payload={},
        event_type=event_type,
        aggregate_type=event_type.split(".")[0],
        aggregate_id=agg_id,
        stream_id=f"{event_type.split('.')[0]}:{agg_id}",
        organization_id=_ORG,
    )


@pytest.fixture
def engine() -> ProjectionEngine:
    return ProjectionEngine()


class TestProjectionEngineRegistration:
    def test_register_handler(self, engine: ProjectionEngine) -> None:
        received: list[EventEnvelope] = []

        def handler(ev: EventEnvelope) -> None:
            received.append(ev)

        engine.register("test_proj", "campaign.Created", handler)
        assert "test_proj" in engine.registered_projections()

    def test_register_all_handler(self, engine: ProjectionEngine) -> None:
        counts: list[int] = [0]

        def handler(ev: EventEnvelope) -> None:
            counts[0] += 1

        engine.register_all("catch_all", handler)
        assert "catch_all" in engine.registered_projections()

    def test_multiple_projections_same_event(self, engine: ProjectionEngine) -> None:
        calls: list[str] = []

        engine.register("proj_a", "campaign.Created", lambda ev: calls.append("a"))
        engine.register("proj_b", "campaign.Created", lambda ev: calls.append("b"))
        assert len(engine.registered_projections()) == 2


class TestProjectionEngineProcessing:
    @pytest.mark.asyncio
    async def test_process_dispatches_to_handler(self, engine: ProjectionEngine) -> None:
        received: list[EventEnvelope] = []

        def handler(ev: EventEnvelope) -> None:
            received.append(ev)

        engine.register("p", "campaign.Created", handler)
        ev = _env("campaign.Created")
        await engine.process(ev)
        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_process_wrong_type_not_dispatched(self, engine: ProjectionEngine) -> None:
        received: list[EventEnvelope] = []

        def handler(ev: EventEnvelope) -> None:
            received.append(ev)

        engine.register("p", "campaign.Created", handler)
        await engine.process(_env("campaign.Deleted"))
        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_catch_all_receives_everything(self, engine: ProjectionEngine) -> None:
        received: list[EventEnvelope] = []

        def handler(ev: EventEnvelope) -> None:
            received.append(ev)

        engine.register_all("catch_all", handler)
        await engine.process(_env("campaign.Created"))
        await engine.process(_env("evidence.EvidenceCollected"))
        assert len(received) == 2

    @pytest.mark.asyncio
    async def test_process_increments_counter(self, engine: ProjectionEngine) -> None:
        engine.register("p", "t.T", lambda ev: None)
        for _ in range(5):
            await engine.process(_env("t.T"))
        assert engine.events_processed == 5

    @pytest.mark.asyncio
    async def test_process_batch(self, engine: ProjectionEngine) -> None:
        received: list[EventEnvelope] = []

        def handler(ev: EventEnvelope) -> None:
            received.append(ev)

        engine.register("p", "t.T", handler)
        envs = [_env("t.T") for _ in range(10)]
        await engine.process_batch(envs)
        assert len(received) == 10

    @pytest.mark.asyncio
    async def test_handler_exception_raises_projection_error(self, engine: ProjectionEngine) -> None:
        def failing_handler(ev: EventEnvelope) -> None:
            raise RuntimeError("intentional failure")

        engine.register("fail_proj", "t.T", failing_handler)
        with pytest.raises(ProjectionError) as exc_info:
            await engine.process(_env("t.T"))
        assert exc_info.value.projection_name == "fail_proj"

    @pytest.mark.asyncio
    async def test_projection_position_tracked(self, engine: ProjectionEngine) -> None:
        engine.register("p", "t.T", lambda ev: None)
        store = InMemoryEventStore()
        for i in range(5):
            await store.append(EventBatch(
                stream_id=f"t:a{i}",
                organization_id=_ORG,
                events=(_env("t.T", f"a{i}"),),
            ))
        count = await engine.catch_up(store, _ORG)
        assert count == 5


class TestProjectionCheckpoints:
    @pytest.mark.asyncio
    async def test_save_and_load_checkpoint(self) -> None:
        repo = InMemoryCheckpointRepository()
        cp = ProjectionCheckpoint(
            projection_id="p1",
            projection_name="test",
            last_global_position=42,
            last_processed_at=_NOW,
        )
        await repo.save(cp)
        loaded = await repo.load("p1")
        assert loaded is not None
        assert loaded.last_global_position == 42

    @pytest.mark.asyncio
    async def test_load_missing_returns_none(self) -> None:
        repo = InMemoryCheckpointRepository()
        assert await repo.load("nonexistent") is None

    @pytest.mark.asyncio
    async def test_delete_checkpoint(self) -> None:
        repo = InMemoryCheckpointRepository()
        cp = ProjectionCheckpoint(
            projection_id="p2",
            projection_name="x",
            last_global_position=5,
            last_processed_at=_NOW,
        )
        await repo.save(cp)
        await repo.delete("p2")
        assert await repo.load("p2") is None

    @pytest.mark.asyncio
    async def test_engine_make_checkpoint(self) -> None:
        engine = ProjectionEngine()
        cp = engine.make_checkpoint("p1", "test", 100, events_processed=50)
        assert cp.projection_id == "p1"
        assert cp.last_global_position == 100
        assert cp.state == ProjectionState.LIVE


class TestReadModelRepository:
    @pytest.mark.asyncio
    async def test_save_and_load(self) -> None:
        repo = InMemoryReadModelRepository()

        class FakeModel:
            model_type = "test_model"
            organization_id = _ORG

        m = FakeModel()
        await repo.save(m)
        loaded = await repo.load("test_model", _ORG)
        assert loaded is m

    @pytest.mark.asyncio
    async def test_load_missing_returns_none(self) -> None:
        repo = InMemoryReadModelRepository()
        assert await repo.load("missing", _ORG) is None

    @pytest.mark.asyncio
    async def test_list_types(self) -> None:
        repo = InMemoryReadModelRepository()

        class M1:
            model_type = "type_a"
            organization_id = _ORG

        class M2:
            model_type = "type_b"
            organization_id = _ORG

        await repo.save(M1())
        await repo.save(M2())
        types = await repo.list_types(_ORG)
        assert set(types) == {"type_a", "type_b"}


class TestEventBus:
    @pytest.mark.asyncio
    async def test_subscribe_and_receive(self) -> None:
        bus = InMemoryEventBus()
        received: list[EventEnvelope] = []
        bus.subscribe("campaign.Created", lambda ev: received.append(ev))
        ev = _env("campaign.Created")
        await bus.publish_one(ev)
        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_subscribe_all(self) -> None:
        bus = InMemoryEventBus()
        received: list[EventEnvelope] = []
        bus.subscribe_all(lambda ev: received.append(ev))
        await bus.publish_one(_env("campaign.Created"))
        await bus.publish_one(_env("evidence.Collected"))
        assert len(received) == 2

    @pytest.mark.asyncio
    async def test_publish_multiple(self) -> None:
        bus = InMemoryEventBus()
        received: list[EventEnvelope] = []
        bus.subscribe_all(lambda ev: received.append(ev))
        await bus.publish([_env("t.A"), _env("t.B"), _env("t.C")])
        assert len(received) == 3

    @pytest.mark.asyncio
    async def test_unsubscribe(self) -> None:
        bus = InMemoryEventBus()
        received: list[EventEnvelope] = []
        def handler(ev):
            return received.append(ev)
        bus.subscribe("t.T", handler)
        bus.unsubscribe("t.T", handler)
        await bus.publish_one(_env("t.T"))
        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_publish_log(self) -> None:
        bus = InMemoryEventBus()
        await bus.publish_one(_env("t.T"))
        assert len(bus.published) == 1

    @pytest.mark.asyncio
    async def test_clear_log(self) -> None:
        bus = InMemoryEventBus()
        await bus.publish_one(_env("t.T"))
        bus.clear_log()
        assert len(bus.published) == 0

    @pytest.mark.asyncio
    async def test_wrong_type_not_dispatched(self) -> None:
        bus = InMemoryEventBus()
        received: list[EventEnvelope] = []
        bus.subscribe("campaign.Created", lambda ev: received.append(ev))
        await bus.publish_one(_env("campaign.Deleted"))
        assert len(received) == 0
