"""Platform domain events — Sprint 24.

PlatformEvent and EventEnvelope: the canonical transport layer for the
Enterprise AI Security Data Platform.

Design principle: existing bounded-context domain events (CampaignEvent,
EvidenceEvent, etc.) are NOT modified. EventEnvelope wraps any of them as
an opaque `payload: object` — this is the anti-corruption layer that
decouples the platform from individual bounded-context schemas.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from redforge.domain.platform.value_objects import (
    CausationId,
    CorrelationId,
    EventMetadata,
    EventVersion,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _new_event_id() -> str:
    from ulid import ULID

    return str(ULID())


# ── PlatformEvent base ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class PlatformEvent:
    """Base class for events that originate within the Platform bounded context.

    Distinct from domain events in other bounded contexts (which are wrapped
    via EventEnvelope). PlatformEvents represent platform-internal state
    changes: projection failures, snapshot created, timeline rebuilt, etc.
    """

    event_id: str = field(default_factory=_new_event_id)
    occurred_at: datetime = field(default_factory=_utc_now)

    @property
    def event_type(self) -> str:
        return f"platform.{type(self).__name__}"


@dataclass(frozen=True)
class ProjectionFailed(PlatformEvent):
    """Emitted when a projection encounters a fatal error."""

    projection_id: str = ""
    projection_name: str = ""
    error_message: str = ""
    failed_at_position: int = 0


@dataclass(frozen=True)
class ProjectionCaughtUp(PlatformEvent):
    """Emitted when a projection finishes replaying and goes live."""

    projection_id: str = ""
    projection_name: str = ""
    caught_up_at_position: int = 0
    events_replayed: int = 0


@dataclass(frozen=True)
class SnapshotCreated(PlatformEvent):
    """Emitted when an aggregate snapshot is persisted."""

    aggregate_type: str = ""
    aggregate_id: str = ""
    snapshot_version: int = 0
    global_position_at_snapshot: int = 0


@dataclass(frozen=True)
class ReplayStarted(PlatformEvent):
    """Emitted when a replay operation begins."""

    replay_id: str = ""
    filter_description: str = ""
    from_position: int = 0


@dataclass(frozen=True)
class ReplayCompleted(PlatformEvent):
    """Emitted when a replay operation completes."""

    replay_id: str = ""
    events_replayed: int = 0
    from_position: int = 0
    to_position: int = 0


# ── EventEnvelope ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    """The canonical transport unit of the Platform data backbone.

    Wraps ANY existing bounded-context domain event without modifying it.
    The `payload` carries the actual domain event as an opaque object —
    projection handlers cast it to the expected type after checking
    `event_type`.

    Global position is assigned by the EventStore on append and is
    monotonically increasing across ALL streams. Stream position is
    monotonically increasing within a single stream only.

    Multi-tenancy is enforced via `organization_id`: all queries and
    projections MUST filter by it.
    """

    event_id: str
    stream_id: str
    stream_position: int
    global_position: int
    event_type: str
    aggregate_type: str
    aggregate_id: str
    organization_id: str
    payload: object
    metadata: EventMetadata
    occurred_at: datetime
    recorded_at: datetime

    def __lt__(self, other: EventEnvelope) -> bool:
        return self.global_position < other.global_position

    @property
    def correlation_id(self) -> str:
        return str(self.metadata.correlation_id)

    @property
    def causation_id(self) -> str | None:
        if self.metadata.causation_id is None:
            return None
        return str(self.metadata.causation_id)

    @property
    def schema_version(self) -> EventVersion:
        return self.metadata.schema_version

    def with_metadata(self, key: str, value: str) -> EventEnvelope:
        return EventEnvelope(
            event_id=self.event_id,
            stream_id=self.stream_id,
            stream_position=self.stream_position,
            global_position=self.global_position,
            event_type=self.event_type,
            aggregate_type=self.aggregate_type,
            aggregate_id=self.aggregate_id,
            organization_id=self.organization_id,
            payload=self.payload,
            metadata=self.metadata.with_custom(key, value),
            occurred_at=self.occurred_at,
            recorded_at=self.recorded_at,
        )


def make_envelope(
    *,
    payload: object,
    event_type: str,
    aggregate_type: str,
    aggregate_id: str,
    stream_id: str,
    organization_id: str,
    correlation_id: str | CorrelationId | None = None,
    causation_id: str | CausationId | None = None,
    occurred_at: datetime | None = None,
    actor_id: str | None = None,
    actor_type: str | None = None,
) -> EventEnvelope:
    """Factory that builds an EventEnvelope before it is stored.

    Stream position and global position are set to 0 and will be replaced
    by the EventStore on append. The EventStore is the single authority for
    assigning monotonic positions.
    """
    if correlation_id is None:
        corr = CorrelationId.generate()
    elif isinstance(correlation_id, str):
        corr = CorrelationId.from_string(correlation_id)
    else:
        corr = correlation_id

    caus: CausationId | None = None
    if causation_id is not None:
        if isinstance(causation_id, str):
            caus = CausationId.from_string(causation_id)
        else:
            caus = causation_id

    now = _utc_now()
    return EventEnvelope(
        event_id=_new_event_id(),
        stream_id=stream_id,
        stream_position=0,
        global_position=0,
        event_type=event_type,
        aggregate_type=aggregate_type,
        aggregate_id=aggregate_id,
        organization_id=organization_id,
        payload=payload,
        metadata=EventMetadata(
            correlation_id=corr,
            causation_id=caus,
            actor_id=actor_id,
            actor_type=actor_type,
        ),
        occurred_at=occurred_at or now,
        recorded_at=now,
    )


# ── EventBatch ────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class EventBatch:
    """A group of envelopes to be appended atomically to one stream.

    All events in a batch must belong to the same stream_id and
    organization_id. The EventStore will reject mixed-stream batches.
    """

    stream_id: str
    organization_id: str
    events: tuple[EventEnvelope, ...]
    expected_stream_version: int | None = None

    def __post_init__(self) -> None:
        if not self.events:
            raise ValueError("EventBatch must contain at least one event")
        for ev in self.events:
            if ev.stream_id != self.stream_id:
                raise ValueError(
                    f"EventBatch stream_id mismatch: expected {self.stream_id!r}, "
                    f"got {ev.stream_id!r} for event {ev.event_id}"
                )
            if ev.organization_id != self.organization_id:
                raise ValueError(
                    f"EventBatch organization_id mismatch: expected "
                    f"{self.organization_id!r}, got {ev.organization_id!r}"
                )


# ── EventStream ────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class EventStream:
    """An ordered, immutable view of events for a single stream.

    Returned by EventStore.read_stream(). The version is the stream-local
    position of the last event.
    """

    stream_id: str
    organization_id: str
    events: tuple[EventEnvelope, ...]
    version: int
    is_empty: bool

    @classmethod
    def empty(cls, stream_id: str, organization_id: str) -> EventStream:
        return cls(
            stream_id=stream_id,
            organization_id=organization_id,
            events=(),
            version=-1,
            is_empty=True,
        )

    @classmethod
    def from_envelopes(
        cls,
        stream_id: str,
        organization_id: str,
        envelopes: list[EventEnvelope],
    ) -> EventStream:
        sorted_events = tuple(sorted(envelopes, key=lambda e: e.stream_position))
        version = sorted_events[-1].stream_position if sorted_events else -1
        return cls(
            stream_id=stream_id,
            organization_id=organization_id,
            events=sorted_events,
            version=version,
            is_empty=not bool(sorted_events),
        )


# ── EventSnapshot ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class EventSnapshot:
    """A point-in-time snapshot of an aggregate's projected state.

    Allows replay to start from the snapshot rather than from the beginning
    of the stream, reducing replay time for long-lived aggregates.

    `state` is stored as a plain dict to remain storage-agnostic.
    `global_position_at_snapshot` is the global position of the last event
    included in this snapshot.
    """

    snapshot_id: str
    aggregate_type: str
    aggregate_id: str
    organization_id: str
    state: dict[str, Any]
    stream_version_at_snapshot: int
    global_position_at_snapshot: int
    created_at: datetime
    schema_version: EventVersion = field(default_factory=EventVersion.v1)

    def is_newer_than(self, other: EventSnapshot) -> bool:
        return self.global_position_at_snapshot > other.global_position_at_snapshot
