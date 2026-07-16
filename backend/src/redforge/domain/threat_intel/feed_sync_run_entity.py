"""`FeedSyncRun` aggregate root — M22 Phase 2 (Feed Synchronization
Foundation).

One `FeedSyncRun` is the durable execution-history record for a single
synchronization attempt of a `Feed` (which itself may internally
retry several times via `RetryExecutor` before this run is finalized
as SUCCEEDED or FAILED — `retry_attempts_used` records how many of
those internal attempts were consumed).

Deliberately its own aggregate, not a value object embedded on `Feed`:
execution history is unbounded over a feed's lifetime and must be
independently paginated/queried, exactly the collection-growth problem
the M22 Hardening Review flagged for `AttackPath.steps`.
"""

from __future__ import annotations

from datetime import UTC, datetime

from redforge.domain.threat_intel.feed_events import (
    FeedSyncRunFailed,
    FeedSyncRunStarted,
    FeedSyncRunSucceeded,
)
from redforge.domain.threat_intel.feed_value_objects import FeedSyncRunStatus, FeedSyncTrigger

_TERMINAL_STATUSES: frozenset[FeedSyncRunStatus] = frozenset(
    {FeedSyncRunStatus.SUCCEEDED, FeedSyncRunStatus.FAILED}
)


class FeedSyncRunAlreadyFinalizedError(ValueError):
    """Raised when `mark_succeeded`/`mark_failed` is called on a run
    that is not currently RUNNING. Inherits `ValueError` rather than
    `RedForgeError`, mirroring `domain.investigations.exceptions
    .InvalidStatusTransitionError` — this is an in-process programmer
    invariant violation (the orchestration service calling its own
    finalize method twice), never a condition an API caller can
    trigger directly, so it is not mapped to an HTTP status by
    `ErrorHandlerMiddleware`."""

    def __init__(self, run_id: str, current_status: str) -> None:
        super().__init__(f"FeedSyncRun {run_id} is not RUNNING (current: {current_status})")


class FeedSyncRun:
    """Aggregate root for one execution-history record of a `Feed`
    synchronization attempt."""

    __slots__ = (
        "_checkpoint_after",
        "_checkpoint_before",
        "_created_by",
        "_error_message",
        "_events",
        "_feed_id",
        "_finished_at",
        "_id",
        "_items_failed",
        "_items_fetched",
        "_items_processed",
        "_retry_attempts_used",
        "_started_at",
        "_status",
        "_trigger",
    )

    def __init__(
        self,
        *,
        id: str,
        feed_id: str,
        status: FeedSyncRunStatus,
        trigger: FeedSyncTrigger,
        checkpoint_before: str | None,
        checkpoint_after: str | None,
        items_fetched: int,
        items_processed: int,
        items_failed: int,
        retry_attempts_used: int,
        error_message: str | None,
        started_at: datetime,
        finished_at: datetime | None,
        created_by: str,
    ) -> None:
        self._id = id
        self._feed_id = feed_id
        self._status = status
        self._trigger = trigger
        self._checkpoint_before = checkpoint_before
        self._checkpoint_after = checkpoint_after
        self._items_fetched = items_fetched
        self._items_processed = items_processed
        self._items_failed = items_failed
        self._retry_attempts_used = retry_attempts_used
        self._error_message = error_message
        self._started_at = started_at
        self._finished_at = finished_at
        self._created_by = created_by
        self._events: list[FeedSyncRunStarted | FeedSyncRunSucceeded | FeedSyncRunFailed] = []

    # ── Read accessors ──────────────────────────────────────────────────

    @property
    def id(self) -> str:
        return self._id

    @property
    def feed_id(self) -> str:
        return self._feed_id

    @property
    def status(self) -> FeedSyncRunStatus:
        return self._status

    @property
    def trigger(self) -> FeedSyncTrigger:
        return self._trigger

    @property
    def checkpoint_before(self) -> str | None:
        return self._checkpoint_before

    @property
    def checkpoint_after(self) -> str | None:
        return self._checkpoint_after

    @property
    def items_fetched(self) -> int:
        return self._items_fetched

    @property
    def items_processed(self) -> int:
        return self._items_processed

    @property
    def items_failed(self) -> int:
        return self._items_failed

    @property
    def retry_attempts_used(self) -> int:
        return self._retry_attempts_used

    @property
    def error_message(self) -> str | None:
        return self._error_message

    @property
    def started_at(self) -> datetime:
        return self._started_at

    @property
    def finished_at(self) -> datetime | None:
        return self._finished_at

    @property
    def created_by(self) -> str:
        return self._created_by

    @property
    def is_terminal(self) -> bool:
        return self._status in _TERMINAL_STATUSES

    # ── Factory ──────────────────────────────────────────────────────────

    @classmethod
    def start(
        cls,
        *,
        id: str,
        feed_id: str,
        trigger: FeedSyncTrigger,
        checkpoint_before: str | None,
        created_by: str,
        now: datetime | None = None,
    ) -> FeedSyncRun:
        now = now or datetime.now(UTC)
        run = cls(
            id=id,
            feed_id=feed_id,
            status=FeedSyncRunStatus.RUNNING,
            trigger=trigger,
            checkpoint_before=checkpoint_before,
            checkpoint_after=None,
            items_fetched=0,
            items_processed=0,
            items_failed=0,
            retry_attempts_used=0,
            error_message=None,
            started_at=now,
            finished_at=None,
            created_by=created_by,
        )
        run._events.append(
            FeedSyncRunStarted(
                run_id=id, feed_id=feed_id, trigger=trigger.value, occurred_at=now
            )
        )
        return run

    # ── Finalization ─────────────────────────────────────────────────────

    def mark_succeeded(
        self,
        *,
        checkpoint_after: str | None,
        items_fetched: int,
        items_processed: int,
        items_failed: int,
        retry_attempts_used: int,
        now: datetime | None = None,
    ) -> None:
        if self._status is not FeedSyncRunStatus.RUNNING:
            raise FeedSyncRunAlreadyFinalizedError(self._id, self._status.value)
        now = now or datetime.now(UTC)
        self._status = FeedSyncRunStatus.SUCCEEDED
        self._checkpoint_after = checkpoint_after
        self._items_fetched = items_fetched
        self._items_processed = items_processed
        self._items_failed = items_failed
        self._retry_attempts_used = retry_attempts_used
        self._finished_at = now
        self._events.append(
            FeedSyncRunSucceeded(
                run_id=self._id,
                feed_id=self._feed_id,
                items_processed=items_processed,
                retry_attempts_used=retry_attempts_used,
                occurred_at=now,
            )
        )

    def mark_failed(
        self,
        *,
        error_message: str,
        retry_attempts_used: int,
        items_fetched: int = 0,
        items_processed: int = 0,
        items_failed: int = 0,
        now: datetime | None = None,
    ) -> None:
        if self._status is not FeedSyncRunStatus.RUNNING:
            raise FeedSyncRunAlreadyFinalizedError(self._id, self._status.value)
        now = now or datetime.now(UTC)
        self._status = FeedSyncRunStatus.FAILED
        self._error_message = error_message
        self._items_fetched = items_fetched
        self._items_processed = items_processed
        self._items_failed = items_failed
        self._retry_attempts_used = retry_attempts_used
        self._finished_at = now
        self._events.append(
            FeedSyncRunFailed(
                run_id=self._id,
                feed_id=self._feed_id,
                error_message=error_message,
                retry_attempts_used=retry_attempts_used,
                occurred_at=now,
            )
        )

    # ── Domain events ────────────────────────────────────────────────────

    def collect_events(
        self,
    ) -> list[FeedSyncRunStarted | FeedSyncRunSucceeded | FeedSyncRunFailed]:
        events = list(self._events)
        self._events.clear()
        return events
