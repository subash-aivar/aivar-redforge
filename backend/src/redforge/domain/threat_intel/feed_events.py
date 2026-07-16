"""Domain events for the Feed Synchronization Foundation
sub-context — M22 Phase 2.

Collected by `Feed`/`FeedSyncRun` aggregate methods and returned via
`collect_events()`; dispatched (or, honestly, simply discarded after
being exercised) by the application service — no event bus exists yet
in this codebase, the exact same disclosed limitation M21's
`InvestigationCase` and M22 Phase 1's `ReferenceDataIngestionRecord`
events already carry. Frozen-dataclass + union-alias pattern, per
`domain/investigations/events.py` (M21) and
`domain/threat_intel/reference_data_events.py` (M22 Phase 1).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class FeedRegistered:
    """Fired when a new `Feed` is registered."""

    feed_id: str
    feed_key: str
    source_kind: str
    scope: str
    organization_id: str | None
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class FeedActivated:
    feed_id: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class FeedPaused:
    feed_id: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class FeedDisabled:
    feed_id: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class FeedSyncRunStarted:
    """Fired when a `FeedSyncRun` transitions PENDING -> RUNNING."""

    run_id: str
    feed_id: str
    trigger: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class FeedSyncRunSucceeded:
    run_id: str
    feed_id: str
    items_processed: int
    retry_attempts_used: int
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class FeedSyncRunFailed:
    run_id: str
    feed_id: str
    error_message: str
    retry_attempts_used: int
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


FeedDomainEvent = (
    FeedRegistered
    | FeedActivated
    | FeedPaused
    | FeedDisabled
    | FeedSyncRunStarted
    | FeedSyncRunSucceeded
    | FeedSyncRunFailed
)
