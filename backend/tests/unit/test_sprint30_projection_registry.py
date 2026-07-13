"""Sprint 30 — Projection registry and real-handler replay tests.

Verifies:
- ProjectionRegistry registers projections correctly
- Duplicate projection_name is rejected at registration
- Empty projection_name is rejected
- validate() raises when registry is empty
- register_all_with() wires all handlers into an engine
- Replay engine with real handlers calls them on process()
- Replay engine with real handlers skips already-checkpointed events
- Multiple projections receive the same event
- Handler failure propagates and increments engine error count
- In-process dedup prevents double-execution
- build_runtime_container produces a non-empty registry
- Startup validation fails when registry is empty (ProjectionRegistrationError)
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from redforge.application.platform.idempotent_projection_engine import (
    IdempotentProjectionEngine,
)
from redforge.application.platform.projection_engine import InMemoryReadModelRepository
from redforge.application.platform.projection_registry import (
    ProjectionRegistrationError,
    ProjectionRegistry,
)
from redforge.application.platform.projections.base import ProjectionBase
from redforge.application.platform.projections.campaign_projection import (
    CampaignProjection,
)
from redforge.application.platform.projections.inventory_projection import (
    InventoryProjection,
)
from redforge.domain.platform.events import EventEnvelope
from redforge.domain.platform.value_objects import CausationId, CorrelationId, EventMetadata


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _make_envelope(
    event_type: str = "campaign.CampaignCreated",
    event_id: str = "ev-001",
    global_position: int = 1,
    organization_id: str = "org-test",
) -> EventEnvelope:
    return EventEnvelope(
        event_id=event_id,
        stream_id=f"test:agg-{event_id}",
        stream_position=1,
        global_position=global_position,
        event_type=event_type,
        aggregate_type="campaign",
        aggregate_id="agg-1",
        organization_id=organization_id,
        payload={},
        metadata=EventMetadata(
            correlation_id=CorrelationId("corr-1"),
            causation_id=CausationId("caus-1"),
            schema_version=1,
        ),
        occurred_at=_utc_now(),
        recorded_at=_utc_now(),
    )


def _make_checkpoint_repo() -> AsyncMock:
    mock = AsyncMock()
    mock.load = AsyncMock(return_value=None)
    mock.save = AsyncMock()
    return mock


# ── ProjectionRegistry unit tests ─────────────────────────────────────────────


class TestProjectionRegistry:
    def test_registers_projection(self) -> None:
        registry = ProjectionRegistry()
        repo = InMemoryReadModelRepository()
        registry.register(CampaignProjection(repo))
        assert "campaign" in registry.projection_names

    def test_rejects_duplicate_name(self) -> None:
        registry = ProjectionRegistry()
        repo = InMemoryReadModelRepository()
        registry.register(CampaignProjection(repo))
        with pytest.raises(ProjectionRegistrationError, match="campaign"):
            registry.register(CampaignProjection(repo))

    def test_rejects_empty_name(self) -> None:
        class NoNameProjection(ProjectionBase):
            projection_name = ""

            def register_with(self, engine: object) -> None:
                pass

        registry = ProjectionRegistry()
        with pytest.raises(ProjectionRegistrationError, match="projection_name"):
            registry.register(NoNameProjection())

    def test_validate_raises_when_empty(self) -> None:
        registry = ProjectionRegistry()
        with pytest.raises(ProjectionRegistrationError, match="empty"):
            registry.validate()

    def test_validate_passes_when_populated(self) -> None:
        registry = ProjectionRegistry()
        registry.register(CampaignProjection(InMemoryReadModelRepository()))
        registry.validate()  # must not raise

    def test_count_and_info(self) -> None:
        registry = ProjectionRegistry()
        registry.register(CampaignProjection(InMemoryReadModelRepository()))
        registry.register(InventoryProjection(InMemoryReadModelRepository()))
        assert registry.count == 2
        names = registry.projection_names
        assert "campaign" in names
        assert "inventory" in names
        info = registry.info()
        assert len(info) == 2
        assert all("name" in p and "type" in p for p in info)


# ── register_all_with() integration with IdempotentProjectionEngine ───────────


async def test_register_all_with_wires_handlers() -> None:
    """register_all_with() causes engine to have handlers for registered event types."""
    registry = ProjectionRegistry()
    registry.register(CampaignProjection(InMemoryReadModelRepository()))

    repo = _make_checkpoint_repo()
    engine = IdempotentProjectionEngine(repo)
    registry.register_all_with(engine)

    assert "campaign" in engine.registered_projections()


async def test_replay_with_real_handler_executes() -> None:
    """When registry is wired, processing an event calls the real handler."""
    repo = InMemoryReadModelRepository()
    campaign_proj = CampaignProjection(repo)

    registry = ProjectionRegistry()
    registry.register(campaign_proj)

    checkpoint_repo = _make_checkpoint_repo()
    engine = IdempotentProjectionEngine(checkpoint_repo)
    await engine.load_checkpoints()
    registry.register_all_with(engine)

    envelope = _make_envelope("campaign.CampaignCreated", event_id="ev-camp-1")
    await engine.process(envelope)

    # handler must have called _persist, so read model must exist
    model = await repo.load("campaign", "org-test")
    assert model is not None
    assert model.total_campaigns == 1


async def test_replay_with_real_handler_skips_checkpointed_event() -> None:
    """Events at or below checkpoint position are skipped by real handlers."""
    from redforge.domain.platform.value_objects import (
        ProjectionCheckpoint,
        ProjectionState,
    )

    repo = InMemoryReadModelRepository()
    campaign_proj = CampaignProjection(repo)

    existing_cp = ProjectionCheckpoint(
        projection_id="campaign",
        projection_name="campaign",
        last_global_position=10,
        last_processed_at=_utc_now(),
        state=ProjectionState.LIVE,
        events_processed=5,
    )

    checkpoint_repo = AsyncMock()
    checkpoint_repo.load = AsyncMock(return_value=existing_cp)
    checkpoint_repo.save = AsyncMock()

    registry = ProjectionRegistry()
    registry.register(campaign_proj)

    engine = IdempotentProjectionEngine(checkpoint_repo)
    registry.register_all_with(engine)  # register first so load_checkpoints knows the names
    await engine.load_checkpoints()

    # Event at position 5 is BELOW checkpoint 10 → skip
    envelope = _make_envelope("campaign.CampaignCreated", event_id="ev-old", global_position=5)
    await engine.process(envelope)

    assert engine.events_skipped == 1
    # Handler never ran — read model untouched
    model = await repo.load("campaign", "org-test")
    assert model is None


async def test_multiple_projections_receive_same_event() -> None:
    """All projections registered for an event type receive it."""
    repo = InMemoryReadModelRepository()
    campaign_proj = CampaignProjection(repo)
    inventory_proj = InventoryProjection(repo)

    registry = ProjectionRegistry()
    registry.register(campaign_proj)
    registry.register(inventory_proj)

    checkpoint_repo = _make_checkpoint_repo()
    engine = IdempotentProjectionEngine(checkpoint_repo)
    await engine.load_checkpoints()
    registry.register_all_with(engine)

    # inventory.AIAssetCreated is handled by InventoryProjection
    envelope = _make_envelope("inventory.AIAssetCreated", event_id="ev-asset-1")
    await engine.process(envelope)

    model = await repo.load("inventory", "org-test")
    assert model is not None
    assert model.total_assets == 1


async def test_in_session_dedup_prevents_double_execution() -> None:
    """Delivering the same event_id twice executes the handler only once."""
    repo = InMemoryReadModelRepository()
    campaign_proj = CampaignProjection(repo)

    registry = ProjectionRegistry()
    registry.register(campaign_proj)

    checkpoint_repo = _make_checkpoint_repo()
    engine = IdempotentProjectionEngine(checkpoint_repo)
    await engine.load_checkpoints()
    registry.register_all_with(engine)

    envelope = _make_envelope("campaign.CampaignCreated", event_id="ev-dup")
    await engine.process(envelope)
    await engine.process(envelope)  # second delivery — must be skipped

    model = await repo.load("campaign", "org-test")
    assert model is not None
    assert model.total_campaigns == 1  # only 1, not 2
    assert engine.events_skipped >= 1


async def test_handler_failure_propagates_as_projection_error() -> None:
    """A handler that raises causes IdempotentProjectionEngine to raise ProjectionError."""
    from redforge.domain.platform.exceptions import ProjectionError

    class BrokenProjection(ProjectionBase):
        projection_name = "broken"

        def register_with(self, engine: object) -> None:  # type: ignore[override]
            engine.register(  # type: ignore[attr-defined]
                self.projection_name, "campaign.CampaignCreated", self._handle
            )

        async def _handle(self, envelope: EventEnvelope) -> None:
            raise RuntimeError("handler exploded")

    registry = ProjectionRegistry()
    registry.register(BrokenProjection())

    checkpoint_repo = _make_checkpoint_repo()
    engine = IdempotentProjectionEngine(checkpoint_repo)
    await engine.load_checkpoints()
    registry.register_all_with(engine)

    envelope = _make_envelope("campaign.CampaignCreated", event_id="ev-broken")
    with pytest.raises(ProjectionError):
        await engine.process(envelope)

    assert len(engine.errors) == 1


# ── build_runtime_container produces populated registry ───────────────────────


def test_build_runtime_container_has_projection_registry() -> None:
    from redforge.application.platform.runtime_container import build_runtime_container
    from redforge.core.config import Settings

    settings = Settings(
        environment="test",
        database_url="postgresql+asyncpg://x:x@localhost/x",
    )
    container = build_runtime_container(settings)
    assert container.projection_registry.count >= 9
    names = container.projection_registry.projection_names
    assert "campaign" in names
    assert "inventory" in names
    assert "validation" in names
    assert "risk" in names
    assert "intelligence" in names
    assert "evidence" in names
    assert "connector_activity" in names
    assert "asset_timeline" in names
    assert "organization_activity" in names


def test_build_runtime_container_registry_validates() -> None:
    """The built registry must pass validate() (non-empty)."""
    from redforge.application.platform.runtime_container import build_runtime_container
    from redforge.core.config import Settings

    settings = Settings(
        environment="test",
        database_url="postgresql+asyncpg://x:x@localhost/x",
    )
    container = build_runtime_container(settings)
    container.projection_registry.validate()  # must not raise
