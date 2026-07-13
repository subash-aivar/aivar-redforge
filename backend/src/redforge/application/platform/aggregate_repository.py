"""Aggregate rehydration from event stream — Sprint 25.

Provides the write-side of CQRS: given an event stream, replay events onto
an aggregate to reconstruct its current state.

Design rules:
- No imports from infrastructure layer.
- AggregateRehydrator is a Protocol — domain aggregates implement it.
- BaseAggregateRehydrationRepository is the generic engine: it combines
  snapshot load + event replay to minimise the number of events applied.
- Aggregates are never stored as mutable rows — only their events are stored.

The rehydration lifecycle:
    1. Load latest snapshot for (aggregate_type, aggregate_id) if available.
    2. Replay events from (snapshot.stream_version + 1) to HEAD.
    3. Apply each event via apply_event().
    4. Optionally take a new snapshot if the event count exceeds a threshold.

Aggregate authors implement:
    - @classmethod initial_state() → T
    - apply_event(envelope) → void (mutates self OR returns new instance)
    - stream_id property
    - aggregate_type class var
"""

from __future__ import annotations

import dataclasses
from typing import Any, Protocol, runtime_checkable

from redforge.domain.platform.events import EventEnvelope, EventSnapshot
from redforge.domain.platform.value_objects import EventVersion

# ── Rehydrated aggregate protocol ─────────────────────────────────────────


@runtime_checkable
class RehydratedAggregate(Protocol):
    """Protocol that a rehydratable aggregate must satisfy.

    Domain aggregates that want to use rehydration implement this.
    They do NOT inherit from it — duck typing via Protocol.
    """

    aggregate_type: str
    aggregate_id: str
    organization_id: str

    @classmethod
    def from_snapshot(cls, state: dict[str, Any], version: int) -> RehydratedAggregate:
        """Reconstruct aggregate from a persisted snapshot dict."""
        ...

    def apply_event(self, envelope: EventEnvelope) -> None:
        """Apply a single event to update aggregate state."""
        ...

    def to_snapshot_state(self) -> dict[str, Any]:
        """Return JSON-serialisable state dict for snapshot persistence."""
        ...

    @property
    def stream_version(self) -> int:
        """Current version (position of last applied event in stream)."""
        ...


# ── Rehydration result ─────────────────────────────────────────────────────


@dataclasses.dataclass(frozen=True, slots=True)
class RehydrationResult:
    """Result of a rehydration operation.

    Carries the reconstructed aggregate, the version it was rehydrated to,
    and diagnostics about how many events were replayed vs snapshot-loaded.
    """

    aggregate: Any
    stream_version: int
    events_replayed: int
    loaded_from_snapshot: bool
    snapshot_version: int


# ── Aggregate rehydration repository ──────────────────────────────────────


class AggregateRehydrationRepository:
    """Generic rehydration engine: snapshot + event-replay.

    Type parameter T is the aggregate type. Callers inject:
    - event_store: any EventStore implementation
    - snapshot_store: any SnapshotStore implementation
    - aggregate_class: the class object (for from_snapshot and initial_state)

    Usage::

        repo = AggregateRehydrationRepository(
            event_store=store,
            snapshot_store=snapshots,
            aggregate_class=Campaign,
            snapshot_threshold=100,
        )
        result = await repo.load(
            aggregate_type="campaign",
            aggregate_id=campaign_id,
            organization_id=org_id,
        )
        campaign = result.aggregate
    """

    def __init__(
        self,
        event_store: Any,
        snapshot_store: Any,
        aggregate_class: type[Any],
        snapshot_threshold: int = 100,
    ) -> None:
        self._event_store = event_store
        self._snapshot_store = snapshot_store
        self._aggregate_class = aggregate_class
        self._snapshot_threshold = snapshot_threshold

    async def load(
        self,
        aggregate_type: str,
        aggregate_id: str,
        organization_id: str,
    ) -> RehydrationResult | None:
        """Load aggregate state from snapshot + events.

        Returns None if the aggregate does not exist (no events in stream).
        """
        stream_id = f"{aggregate_type}:{aggregate_id}"

        # Step 1: try loading the latest snapshot
        snapshot: EventSnapshot | None = await self._snapshot_store.load_latest_snapshot(
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            organization_id=organization_id,
        )

        # Step 2: determine replay start point
        if snapshot is not None:
            aggregate = self._aggregate_class.from_snapshot(
                snapshot.state,
                snapshot.stream_version_at_snapshot,
            )
            from_stream_position = snapshot.stream_version_at_snapshot + 1
            loaded_from_snapshot = True
            snapshot_version = snapshot.stream_version_at_snapshot
        else:
            aggregate = None
            from_stream_position = 0
            loaded_from_snapshot = False
            snapshot_version = -1

        # Step 3: replay events from store (stream may not exist yet)
        from redforge.domain.platform.exceptions import StreamNotFoundError
        try:
            events = await self._event_store.read_stream(
                stream_id=stream_id,
                organization_id=organization_id,
                from_position=from_stream_position,
            )
        except StreamNotFoundError:
            events = []

        if aggregate is None and not events:
            return None

        events_replayed = 0
        for envelope in events:
            if aggregate is None:
                aggregate = self._build_initial(aggregate_id, organization_id)
            aggregate.apply_event(envelope)
            events_replayed += 1

        if aggregate is None:
            return None

        stream_version = (
            events[-1].stream_position if events else snapshot_version
        )

        result: RehydrationResult = RehydrationResult(
            aggregate=aggregate,
            stream_version=stream_version,
            events_replayed=events_replayed,
            loaded_from_snapshot=loaded_from_snapshot,
            snapshot_version=snapshot_version,
        )

        # Step 4: snapshot if threshold exceeded
        if events_replayed >= self._snapshot_threshold:
            await self._take_snapshot(aggregate, stream_version, organization_id)

        return result

    def _build_initial(
        self,
        aggregate_id: str,
        organization_id: str,
    ) -> Any:
        """Build empty initial aggregate state before any events are applied."""
        if hasattr(self._aggregate_class, "initial_state"):
            return self._aggregate_class.initial_state(
                aggregate_id=aggregate_id,
                organization_id=organization_id,
            )
        raise TypeError(
            f"{self._aggregate_class.__name__} must implement "
            f"initial_state(aggregate_id, organization_id) classmethod"
        )

    async def _take_snapshot(
        self,
        aggregate: Any,
        stream_version: int,
        organization_id: str,
    ) -> None:
        from datetime import UTC, datetime

        from ulid import ULID
        snapshot = EventSnapshot(
            snapshot_id=str(ULID()),
            aggregate_type=aggregate.aggregate_type,
            aggregate_id=aggregate.aggregate_id,
            organization_id=organization_id,
            state=aggregate.to_snapshot_state(),
            stream_version_at_snapshot=stream_version,
            global_position_at_snapshot=0,
            created_at=datetime.now(UTC),
            schema_version=EventVersion.v1(),
        )
        await self._snapshot_store.save_snapshot(snapshot)
