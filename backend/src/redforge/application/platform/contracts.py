"""Platform application contracts — Sprint 24.

All 10 protocol ports for the Enterprise AI Security Data Platform.
These are the boundaries between application and infrastructure layers —
all storage implementations plug in here.

Design rules:
- Every Protocol is @runtime_checkable.
- Methods are async — real implementations will hit I/O.
- No infrastructure imports anywhere in this file.
- Generic types use TypeVar, not concrete implementations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

from redforge.domain.platform.events import EventBatch, EventEnvelope, EventSnapshot
from redforge.domain.platform.read_models import ReadModel
from redforge.domain.platform.value_objects import (
    ProjectionCheckpoint,
    ReplayCursor,
    RetentionPolicy,
)

# ── EventStore ─────────────────────────────────────────────────────────────


@runtime_checkable
class EventStore(Protocol):
    """Append-only, immutable log of EventEnvelopes.

    The EventStore is the single source of truth. It assigns:
    - stream_position: monotonic within a stream
    - global_position: monotonic across all streams

    Expected concurrency behaviour:
    - If `expected_stream_version` is provided in an EventBatch, the store
      MUST raise OptimisticConcurrencyError if the stream's current version
      differs.
    - Appending with expected_stream_version=None skips concurrency checks.
    """

    async def append(self, batch: EventBatch) -> Sequence[EventEnvelope]:
        """Append a batch of events to the store atomically.

        Returns the stored envelopes with assigned positions.
        """
        ...

    async def read_stream(
        self,
        stream_id: str,
        organization_id: str,
        from_position: int = 0,
        max_count: int | None = None,
    ) -> Sequence[EventEnvelope]:
        """Read events from a specific stream in order."""
        ...

    async def read_all(
        self,
        organization_id: str,
        from_global_position: int = 0,
        max_count: int | None = None,
    ) -> Sequence[EventEnvelope]:
        """Read events across all streams for an organisation, globally ordered."""
        ...

    async def stream_version(self, stream_id: str, organization_id: str) -> int:
        """Return the current stream version (-1 if stream does not exist)."""
        ...

    async def event_count(self, organization_id: str) -> int:
        """Return total event count for an organisation."""
        ...

    async def stream_ids(self, organization_id: str) -> Sequence[str]:
        """List all stream IDs for an organisation."""
        ...

    async def read_by_correlation_id(
        self,
        correlation_id: str,
        organization_id: str,
    ) -> Sequence[EventEnvelope]:
        """Read all events sharing a correlation ID within an organisation."""
        ...

    async def read_by_event_type(
        self,
        event_type: str,
        organization_id: str,
        from_global_position: int = 0,
        max_count: int | None = None,
    ) -> Sequence[EventEnvelope]:
        """Read all events of a given type within an organisation."""
        ...

    async def read_by_time_range(
        self,
        organization_id: str,
        from_dt: object,
        to_dt: object,
        max_count: int | None = None,
    ) -> Sequence[EventEnvelope]:
        """Read events within a time range for an organisation."""
        ...

    async def tombstone(
        self,
        stream_id: str,
        event_id: str,
        organization_id: str,
    ) -> None:
        """Mark an event as deleted for GDPR right-to-erasure (DEBT-S26).

        Implementations MUST verify organization_id before tombstoning to
        prevent cross-tenant erasure. The event remains in the log as a
        tombstone marker; its payload is replaced with a redaction notice.
        Raises ValueError if organization_id does not match the event's org.
        """
        ...


# ── EventPublisher ─────────────────────────────────────────────────────────


@runtime_checkable
class PlatformEventPublisher(Protocol):
    """Publishes EventEnvelopes to subscribers.

    Decouples event producers (application services) from projection engines
    and other consumers. Implementations may fan out synchronously, via
    message queue, or via change-data-capture from the event store.
    """

    async def publish(self, envelopes: Sequence[EventEnvelope]) -> None:
        """Publish one or more envelopes to all subscribers."""
        ...

    async def publish_one(self, envelope: EventEnvelope) -> None:
        """Convenience: publish a single envelope."""
        ...


# ── EventSubscriber ────────────────────────────────────────────────────────


@runtime_checkable
class EventSubscriber(Protocol):
    """Subscribes to specific event types from the publisher.

    The registration is type-safe: a handler for "campaign.CampaignCreated"
    will only receive events of that type.
    """

    def subscribe(
        self,
        event_type: str,
        handler: object,
    ) -> None:
        """Register a handler callable for a specific event type."""
        ...

    def subscribe_all(self, handler: object) -> None:
        """Register a handler for ALL event types."""
        ...

    def unsubscribe(self, event_type: str, handler: object) -> None:
        """Remove a previously registered handler."""
        ...


# ── ProjectionEngine ───────────────────────────────────────────────────────


@runtime_checkable
class ProjectionEngine(Protocol):
    """Processes EventEnvelopes and dispatches to registered projections.

    Projections are registered by name and handle specific event types.
    The engine is responsible for:
    - Routing events to the correct projection handlers.
    - Loading/saving ProjectionCheckpoints for fault tolerance.
    - Coordinating catch-up replay on startup.
    """

    async def process(self, envelope: EventEnvelope) -> None:
        """Process a single envelope, dispatching to all matching projections."""
        ...

    async def process_batch(self, envelopes: Sequence[EventEnvelope]) -> None:
        """Process multiple envelopes in order."""
        ...

    async def catch_up(
        self,
        event_store: EventStore,
        organization_id: str,
        from_position: int = 0,
    ) -> int:
        """Replay historical events from `from_position` for an organisation.

        Returns the number of events processed.
        """
        ...

    def register(
        self,
        projection_name: str,
        event_type: str,
        handler: object,
    ) -> None:
        """Register a handler for an event_type under a named projection."""
        ...


# ── ProjectionRepository ───────────────────────────────────────────────────


@runtime_checkable
class ProjectionRepository(Protocol):
    """Persists and retrieves ProjectionCheckpoints."""

    async def save_checkpoint(self, checkpoint: ProjectionCheckpoint) -> None:
        ...

    async def load_checkpoint(
        self, projection_id: str
    ) -> ProjectionCheckpoint | None:
        ...

    async def list_checkpoints(
        self, organization_id: str
    ) -> Sequence[ProjectionCheckpoint]:
        ...


# ── ReadModelRepository ────────────────────────────────────────────────────


@runtime_checkable
class ReadModelRepository(Protocol):
    """Persists and retrieves ReadModels.

    Key is (model_type, organization_id) — there is exactly one ReadModel
    per type per organisation.
    """

    async def save(self, model: ReadModel) -> None:
        ...

    async def load(
        self, model_type: str, organization_id: str
    ) -> ReadModel | None:
        ...

    async def list_types(self, organization_id: str) -> Sequence[str]:
        ...


# ── SnapshotStore ──────────────────────────────────────────────────────────


@runtime_checkable
class SnapshotStore(Protocol):
    """Stores and retrieves EventSnapshots for aggregate state optimisation."""

    async def save_snapshot(self, snapshot: EventSnapshot) -> None:
        ...

    async def load_latest_snapshot(
        self,
        aggregate_type: str,
        aggregate_id: str,
        organization_id: str,
    ) -> EventSnapshot | None:
        ...

    async def list_snapshots(
        self,
        aggregate_type: str,
        organization_id: str,
    ) -> Sequence[EventSnapshot]:
        ...


# ── ReplayEngine ───────────────────────────────────────────────────────────


@runtime_checkable
class ReplayEngine(Protocol):
    """Replays historical events with fine-grained filtering.

    Supports 8 filter dimensions as required by Sprint 24 mission:
    1. By Organization
    2. By Campaign (stream prefix)
    3. By Asset (stream prefix)
    4. By Validation (stream prefix)
    5. By Time Range
    6. By Correlation ID
    7. By Event Type
    8. By Aggregate
    """

    async def replay_organization(
        self,
        organization_id: str,
        from_position: int = 0,
        max_events: int | None = None,
    ) -> AsyncIterator[EventEnvelope]:
        """Replay all events for an organisation."""
        ...

    async def replay_stream(
        self,
        stream_id: str,
        organization_id: str,
        from_stream_position: int = 0,
    ) -> AsyncIterator[EventEnvelope]:
        """Replay all events in a specific stream."""
        ...

    async def replay_aggregate(
        self,
        aggregate_type: str,
        aggregate_id: str,
        organization_id: str,
        from_position: int = 0,
    ) -> AsyncIterator[EventEnvelope]:
        """Replay all events for a specific aggregate."""
        ...

    async def replay_by_time_range(
        self,
        organization_id: str,
        from_dt: object,
        to_dt: object,
        event_types: Sequence[str] | None = None,
    ) -> AsyncIterator[EventEnvelope]:
        """Replay events within a time range, optionally filtered by type."""
        ...

    async def replay_by_correlation_id(
        self,
        correlation_id: str,
        organization_id: str,
    ) -> AsyncIterator[EventEnvelope]:
        """Replay all events sharing a correlation ID."""
        ...

    async def replay_by_event_type(
        self,
        event_type: str,
        organization_id: str,
        from_position: int = 0,
        max_events: int | None = None,
    ) -> AsyncIterator[EventEnvelope]:
        """Replay all events of a given type for an organisation."""
        ...

    async def replay_from_cursor(
        self,
        cursor: ReplayCursor,
        organization_id: str,
        max_events: int | None = None,
    ) -> tuple[Sequence[EventEnvelope], ReplayCursor]:
        """Paginated replay: returns events and an advanced cursor."""
        ...


# ── TimelineRepository ─────────────────────────────────────────────────────


@runtime_checkable
class TimelineRepository(Protocol):
    """Builds and queries timeline views."""

    async def get_timeline(
        self,
        subject_type: str,
        subject_id: str,
        organization_id: str,
        from_position: int = 0,
        max_entries: int | None = None,
    ) -> object:
        """Return a Timeline for the given subject."""
        ...

    async def get_audit_timeline(
        self,
        subject_type: str,
        subject_id: str,
        organization_id: str,
        from_position: int = 0,
        max_entries: int | None = None,
    ) -> object:
        """Return an AuditTimeline with actor attribution."""
        ...


# ── CheckpointRepository ───────────────────────────────────────────────────


@runtime_checkable
class CheckpointRepository(Protocol):
    """Dedicated checkpoint repository (may differ from ProjectionRepository).

    Allows checkpoints to be persisted separately from projection metadata
    for higher-frequency writes.
    """

    async def save(self, checkpoint: ProjectionCheckpoint) -> None:
        ...

    async def load(self, projection_id: str) -> ProjectionCheckpoint | None:
        ...

    async def delete(self, projection_id: str) -> None:
        ...

    async def apply_retention(self, policy: RetentionPolicy) -> int:
        """Remove checkpoints older than the policy allows.

        Returns the number of checkpoints deleted.
        """
        ...
