"""Platform domain value objects — Sprint 24.

Immutable value objects for the Enterprise AI Security Data Platform.
These form the vocabulary for the event sourcing backbone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime

# ── Identity value objects ─────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CorrelationId:
    """Links causally-related events that span bounded contexts.

    A single user action (e.g. "run campaign") may produce events across
    Campaign, Validation, Evidence, and Finding contexts — all sharing one
    CorrelationId.
    """

    value: str

    def __str__(self) -> str:
        return self.value

    @classmethod
    def generate(cls) -> CorrelationId:
        from ulid import ULID

        return cls(value=str(ULID()))

    @classmethod
    def from_string(cls, value: str) -> CorrelationId:
        if not value or not value.strip():
            raise ValueError("CorrelationId cannot be empty")
        return cls(value=value)


@dataclass(frozen=True, slots=True)
class CausationId:
    """The event_id that directly caused the current event.

    Enables causal chain traversal: given an event, walk backwards to the
    initiating action.
    """

    value: str

    def __str__(self) -> str:
        return self.value

    @classmethod
    def from_string(cls, value: str) -> CausationId:
        if not value or not value.strip():
            raise ValueError("CausationId cannot be empty")
        return cls(value=value)


@dataclass(frozen=True, slots=True)
class EventVersion:
    """Schema version for backward-compatible event evolution.

    Allows projection handlers to adapt to multiple event schema versions
    without breaking replay of historical events.
    """

    major: int
    minor: int

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}"

    def is_compatible_with(self, other: EventVersion) -> bool:
        return self.major == other.major

    @classmethod
    def v1(cls) -> EventVersion:
        return cls(major=1, minor=0)

    @classmethod
    def from_string(cls, value: str) -> EventVersion:
        parts = value.split(".")
        if len(parts) != 2:
            raise ValueError(f"Invalid EventVersion format: {value!r}")
        return cls(major=int(parts[0]), minor=int(parts[1]))


@dataclass(frozen=True, slots=True)
class EventMetadata:
    """Envelope-level metadata that travels with every event.

    Stores cross-cutting concerns without polluting domain events.
    All fields except correlation_id are optional because not every event
    has a known causation or explicit schema version.
    """

    correlation_id: CorrelationId
    causation_id: CausationId | None = None
    schema_version: EventVersion = field(default_factory=EventVersion.v1)
    actor_id: str | None = None
    actor_type: str | None = None
    source_service: str = "redforge"
    custom: tuple[tuple[str, str], ...] = ()

    def get_custom(self, key: str) -> str | None:
        for k, v in self.custom:
            if k == key:
                return v
        return None

    def with_custom(self, key: str, value: str) -> EventMetadata:
        existing = {k: v for k, v in self.custom}
        existing[key] = value
        return EventMetadata(
            correlation_id=self.correlation_id,
            causation_id=self.causation_id,
            schema_version=self.schema_version,
            actor_id=self.actor_id,
            actor_type=self.actor_type,
            source_service=self.source_service,
            custom=tuple(sorted(existing.items())),
        )


# ── Retention and policy value objects ────────────────────────────────────


class RetentionCategory(StrEnum):
    """Retention tier for event streams."""

    HOT = "hot"        # immediate access, recent events
    WARM = "warm"      # available but potentially slower
    COLD = "cold"      # archival, accessed rarely
    FROZEN = "frozen"  # compliance archive, immutable, very slow access


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """Defines how long events are kept and at what storage tier.

    Vendor-agnostic: the concrete storage implementation decides how to
    honour these policies. The domain just declares intent.
    """

    retain_days: int
    category: RetentionCategory = RetentionCategory.HOT
    archive_after_days: int | None = None
    delete_after_days: int | None = None

    def __post_init__(self) -> None:
        if self.retain_days <= 0:
            raise ValueError("retain_days must be positive")
        if self.archive_after_days is not None and self.archive_after_days <= 0:
            raise ValueError("archive_after_days must be positive")
        if self.delete_after_days is not None and self.delete_after_days <= 0:
            raise ValueError("delete_after_days must be positive")

    @classmethod
    def default(cls) -> RetentionPolicy:
        return cls(retain_days=365, category=RetentionCategory.HOT)

    @classmethod
    def compliance(cls) -> RetentionPolicy:
        """Seven-year compliance retention."""
        return cls(
            retain_days=2555,
            category=RetentionCategory.WARM,
            archive_after_days=365,
            delete_after_days=2555,
        )

    @classmethod
    def short_lived(cls) -> RetentionPolicy:
        """30-day operational events."""
        return cls(retain_days=30, category=RetentionCategory.HOT)


# ── Projection state value objects ─────────────────────────────────────────


class ProjectionState(StrEnum):
    """Lifecycle state of a running projection."""

    INITIALIZING = "initializing"   # created, not yet started
    CATCHING_UP = "catching_up"     # replaying historical events
    LIVE = "live"                   # processing real-time events
    PAUSED = "paused"               # temporarily halted
    ERROR = "error"                 # failed, needs intervention
    STOPPED = "stopped"             # gracefully stopped


@dataclass(frozen=True, slots=True)
class ProjectionCheckpoint:
    """Records where a projection has processed up to.

    On restart, replay begins from `last_global_position + 1`, not from 0.
    This makes catch-up O(missed events), not O(all events).
    """

    projection_id: str
    projection_name: str
    last_global_position: int
    last_processed_at: datetime
    state: ProjectionState = ProjectionState.LIVE
    error_message: str | None = None
    events_processed: int = 0

    def advance(
        self,
        new_position: int,
        processed_at: datetime,
    ) -> ProjectionCheckpoint:
        return ProjectionCheckpoint(
            projection_id=self.projection_id,
            projection_name=self.projection_name,
            last_global_position=new_position,
            last_processed_at=processed_at,
            state=self.state,
            error_message=self.error_message,
            events_processed=self.events_processed + 1,
        )

    def mark_error(self, error: str) -> ProjectionCheckpoint:
        return ProjectionCheckpoint(
            projection_id=self.projection_id,
            projection_name=self.projection_name,
            last_global_position=self.last_global_position,
            last_processed_at=self.last_processed_at,
            state=ProjectionState.ERROR,
            error_message=error,
            events_processed=self.events_processed,
        )


@dataclass(frozen=True, slots=True)
class ReplayCursor:
    """Position marker for resumable replay operations.

    Replay may be paused (e.g. to rate-limit) and resumed from the cursor
    without re-processing already-seen events.
    """

    global_position: int
    stream_id: str | None = None
    is_exhausted: bool = False

    @classmethod
    def beginning(cls) -> ReplayCursor:
        return cls(global_position=0)

    @classmethod
    def from_position(cls, position: int) -> ReplayCursor:
        if position < 0:
            raise ValueError("ReplayCursor position must be non-negative")
        return cls(global_position=position)

    def advance(self, new_position: int) -> ReplayCursor:
        return ReplayCursor(
            global_position=new_position,
            stream_id=self.stream_id,
        )

    def exhaust(self) -> ReplayCursor:
        return ReplayCursor(
            global_position=self.global_position,
            stream_id=self.stream_id,
            is_exhausted=True,
        )


# ── Timeline value objects ─────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    """A single entry in a timeline view.

    Wraps an EventEnvelope with display-friendly metadata.
    Kept as a value object so timelines can be sorted, deduplicated, etc.
    """

    event_id: str
    event_type: str
    aggregate_type: str
    aggregate_id: str
    occurred_at: datetime
    recorded_at: datetime
    organization_id: str
    correlation_id: str
    summary: str
    details: dict[str, Any]
    global_position: int

    def __lt__(self, other: TimelineEntry) -> bool:
        return self.global_position < other.global_position
