"""`Feed` aggregate root — M22 Phase 2 (Feed Synchronization Foundation).

A `Feed` is the durable configuration + lifecycle state for one
external (or manually-fed) threat-intelligence source that this
platform knows how to schedule and synchronize. It owns:

- identity and scope (GLOBAL catalog feed, or a future TENANT-scoped
  subscription — reusing `IngestionScope` from M22 Phase 1 rather than
  duplicating the same GLOBAL/TENANT discriminator logic)
- lifecycle (`FeedStatus`: DRAFT/ACTIVE/PAUSED/DISABLED)
- scheduling state (`SyncSchedule`, `next_sync_due_at`)
- retry configuration (`RetryPolicy`) — the *configuration*; the
  actual backoff math is `RetryExecutor`'s, applied by the
  orchestration service
- an opaque `checkpoint` cursor advanced only by a successful sync

It deliberately does NOT hold its own sync execution history as an
in-aggregate collection. Per the M22 Hardening Review (Part 2, DDD
Validation — "AttackPath aggregate contains a list[AttackStep] ... an
unbounded collection anti-pattern"): sync run history is `FeedSyncRun`,
a separate aggregate with its own repository, referenced by
`feed_id` — never embedded here.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from redforge.domain.threat_intel.feed_events import (
    FeedActivated,
    FeedDisabled,
    FeedDomainEvent,
    FeedPaused,
    FeedRegistered,
)
from redforge.domain.threat_intel.feed_exceptions import (
    FeedNotActiveError,
    InvalidFeedStatusTransitionError,
)
from redforge.domain.threat_intel.feed_value_objects import (
    FeedSourceKind,
    FeedStatus,
    FeedSyncRunStatus,
    RetryPolicy,
    SyncSchedule,
)
from redforge.domain.threat_intel.reference_data_exceptions import InvalidIngestionScopeError
from redforge.domain.threat_intel.reference_data_value_objects import IngestionScope

if TYPE_CHECKING:
    from redforge.domain.threat_intel.feed_value_objects import FeedKey

_ACTIVATABLE_FROM: frozenset[FeedStatus] = frozenset({FeedStatus.DRAFT, FeedStatus.PAUSED})


class Feed:
    """Aggregate root for one configured, schedulable threat-intel feed."""

    __slots__ = (
        "_checkpoint",
        "_connector_config",
        "_consecutive_failure_count",
        "_created_at",
        "_created_by",
        "_credential_ref",
        "_display_name",
        "_events",
        "_feed_key",
        "_id",
        "_last_sync_completed_at",
        "_last_sync_started_at",
        "_last_sync_status",
        "_next_sync_due_at",
        "_organization_id",
        "_retry_policy",
        "_schedule",
        "_scope",
        "_source_kind",
        "_status",
        "_updated_at",
        "_updated_by",
    )

    def __init__(
        self,
        *,
        id: str,
        feed_key: FeedKey,
        display_name: str,
        source_kind: FeedSourceKind,
        scope: IngestionScope,
        organization_id: str | None,
        status: FeedStatus,
        connector_config: dict[str, Any],
        credential_ref: str | None,
        schedule: SyncSchedule,
        retry_policy: RetryPolicy,
        checkpoint: str | None,
        consecutive_failure_count: int,
        last_sync_started_at: datetime | None,
        last_sync_completed_at: datetime | None,
        last_sync_status: FeedSyncRunStatus | None,
        next_sync_due_at: datetime | None,
        created_at: datetime,
        updated_at: datetime,
        created_by: str,
        updated_by: str,
    ) -> None:
        self._validate_scope(scope, organization_id)
        self._id = id
        self._feed_key = feed_key
        self._display_name = display_name
        self._source_kind = source_kind
        self._scope = scope
        self._organization_id = organization_id
        self._status = status
        self._connector_config = dict(connector_config)
        self._credential_ref = credential_ref
        self._schedule = schedule
        self._retry_policy = retry_policy
        self._checkpoint = checkpoint
        self._consecutive_failure_count = consecutive_failure_count
        self._last_sync_started_at = last_sync_started_at
        self._last_sync_completed_at = last_sync_completed_at
        self._last_sync_status = last_sync_status
        self._next_sync_due_at = next_sync_due_at
        self._created_at = created_at
        self._updated_at = updated_at
        self._created_by = created_by
        self._updated_by = updated_by
        self._events: list[FeedDomainEvent] = []

    @staticmethod
    def _validate_scope(scope: IngestionScope, organization_id: str | None) -> None:
        if scope is IngestionScope.GLOBAL and organization_id is not None:
            raise InvalidIngestionScopeError(
                "GLOBAL-scope feeds must not carry an organization_id "
                f"(got {organization_id!r})"
            )
        if scope is IngestionScope.TENANT and organization_id is None:
            raise InvalidIngestionScopeError("TENANT-scope feeds must carry an organization_id")

    # ── Read accessors ──────────────────────────────────────────────────

    @property
    def id(self) -> str:
        return self._id

    @property
    def feed_key(self) -> FeedKey:
        return self._feed_key

    @property
    def display_name(self) -> str:
        return self._display_name

    @property
    def source_kind(self) -> FeedSourceKind:
        return self._source_kind

    @property
    def scope(self) -> IngestionScope:
        return self._scope

    @property
    def organization_id(self) -> str | None:
        return self._organization_id

    @property
    def status(self) -> FeedStatus:
        return self._status

    @property
    def connector_config(self) -> dict[str, Any]:
        return dict(self._connector_config)

    @property
    def credential_ref(self) -> str | None:
        return self._credential_ref

    @property
    def schedule(self) -> SyncSchedule:
        return self._schedule

    @property
    def retry_policy(self) -> RetryPolicy:
        return self._retry_policy

    @property
    def checkpoint(self) -> str | None:
        return self._checkpoint

    @property
    def consecutive_failure_count(self) -> int:
        return self._consecutive_failure_count

    @property
    def last_sync_started_at(self) -> datetime | None:
        return self._last_sync_started_at

    @property
    def last_sync_completed_at(self) -> datetime | None:
        return self._last_sync_completed_at

    @property
    def last_sync_status(self) -> FeedSyncRunStatus | None:
        return self._last_sync_status

    @property
    def next_sync_due_at(self) -> datetime | None:
        return self._next_sync_due_at

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def updated_at(self) -> datetime:
        return self._updated_at

    @property
    def created_by(self) -> str:
        return self._created_by

    @property
    def updated_by(self) -> str:
        return self._updated_by

    @property
    def is_syncable(self) -> bool:
        """True only when a sync trigger is legal — status is ACTIVE.
        Does not consider whether a run is already in flight; that is
        the orchestration service's advisory-lock + repository-level
        concern (`FeedSyncAlreadyRunningError`)."""
        return self._status is FeedStatus.ACTIVE

    def is_due(self, *, now: datetime) -> bool:
        """True when this feed is ACTIVE and its scheduled next-run time
        has arrived. Used by `FeedSyncRepository.list_due_for_sync` at
        the query layer and re-checked here for any in-process caller."""
        return (
            self.is_syncable
            and self._next_sync_due_at is not None
            and self._next_sync_due_at <= now
        )

    # ── Factory ──────────────────────────────────────────────────────────

    @classmethod
    def register(
        cls,
        *,
        id: str,
        feed_key: FeedKey,
        display_name: str,
        source_kind: FeedSourceKind,
        schedule: SyncSchedule,
        actor_id: str,
        scope: IngestionScope = IngestionScope.GLOBAL,
        organization_id: str | None = None,
        connector_config: dict[str, Any] | None = None,
        credential_ref: str | None = None,
        retry_policy: RetryPolicy | None = None,
        now: datetime | None = None,
    ) -> Feed:
        """Register a new feed in DRAFT status. Must be explicitly
        `activate()`-d before it becomes eligible for synchronization —
        registration alone never schedules a sync."""
        now = now or datetime.now(UTC)
        feed = cls(
            id=id,
            feed_key=feed_key,
            display_name=display_name,
            source_kind=source_kind,
            scope=scope,
            organization_id=organization_id,
            status=FeedStatus.DRAFT,
            connector_config=connector_config or {},
            credential_ref=credential_ref,
            schedule=schedule,
            retry_policy=retry_policy or RetryPolicy(),
            checkpoint=None,
            consecutive_failure_count=0,
            last_sync_started_at=None,
            last_sync_completed_at=None,
            last_sync_status=None,
            next_sync_due_at=None,
            created_at=now,
            updated_at=now,
            created_by=actor_id,
            updated_by=actor_id,
        )
        feed._events.append(
            FeedRegistered(
                feed_id=id,
                feed_key=feed_key.value,
                source_kind=source_kind.value,
                scope=scope.value,
                organization_id=organization_id,
                occurred_at=now,
            )
        )
        return feed

    # ── Lifecycle transitions ────────────────────────────────────────────

    def activate(self, *, actor_id: str, now: datetime | None = None) -> None:
        if self._status not in _ACTIVATABLE_FROM:
            raise InvalidFeedStatusTransitionError(self._status.value, FeedStatus.ACTIVE.value)
        now = now or datetime.now(UTC)
        self._status = FeedStatus.ACTIVE
        # A feed becoming ACTIVE for the first time (or resuming from
        # PAUSED with no due date carried over) is immediately eligible
        # — the scheduler worker will pick it up on its next poll
        # rather than waiting a full interval for its first sync.
        if self._next_sync_due_at is None or self._next_sync_due_at < now:
            self._next_sync_due_at = now
        self._updated_at = now
        self._updated_by = actor_id
        self._events.append(FeedActivated(feed_id=self._id, occurred_at=now))

    def pause(self, *, actor_id: str, now: datetime | None = None) -> None:
        if self._status is not FeedStatus.ACTIVE:
            raise InvalidFeedStatusTransitionError(self._status.value, FeedStatus.PAUSED.value)
        now = now or datetime.now(UTC)
        self._status = FeedStatus.PAUSED
        self._next_sync_due_at = None
        self._updated_at = now
        self._updated_by = actor_id
        self._events.append(FeedPaused(feed_id=self._id, occurred_at=now))

    def disable(self, *, actor_id: str, now: datetime | None = None) -> None:
        if self._status is FeedStatus.DISABLED:
            raise InvalidFeedStatusTransitionError(self._status.value, FeedStatus.DISABLED.value)
        now = now or datetime.now(UTC)
        self._status = FeedStatus.DISABLED
        self._next_sync_due_at = None
        self._updated_at = now
        self._updated_by = actor_id
        self._events.append(FeedDisabled(feed_id=self._id, occurred_at=now))

    def update_configuration(
        self,
        *,
        actor_id: str,
        display_name: str | None = None,
        connector_config: dict[str, Any] | None = None,
        credential_ref: str | None = None,
        schedule: SyncSchedule | None = None,
        retry_policy: RetryPolicy | None = None,
        now: datetime | None = None,
    ) -> None:
        """CRUD-level configuration update. Never changes `status`,
        `checkpoint`, or scheduling-run bookkeeping — those are owned by
        the lifecycle transitions and sync-recording methods."""
        if display_name is not None:
            self._display_name = display_name
        if connector_config is not None:
            self._connector_config = dict(connector_config)
        if credential_ref is not None:
            self._credential_ref = credential_ref
        if schedule is not None:
            self._schedule = schedule
        if retry_policy is not None:
            self._retry_policy = retry_policy
        self._updated_at = now or datetime.now(UTC)
        self._updated_by = actor_id

    # ── Sync bookkeeping (called only by the orchestration service) ─────

    def record_sync_started(self, *, now: datetime | None = None) -> None:
        if not self.is_syncable:
            raise FeedNotActiveError(self._id, self._status.value)
        now = now or datetime.now(UTC)
        self._last_sync_started_at = now
        self._last_sync_status = FeedSyncRunStatus.RUNNING
        self._updated_at = now

    def record_sync_succeeded(
        self,
        *,
        checkpoint: str | None,
        now: datetime | None = None,
    ) -> None:
        now = now or datetime.now(UTC)
        if checkpoint is not None:
            self._checkpoint = checkpoint
        self._consecutive_failure_count = 0
        self._last_sync_completed_at = now
        self._last_sync_status = FeedSyncRunStatus.SUCCEEDED
        if self.is_syncable:
            self._next_sync_due_at = now + timedelta(seconds=self._schedule.interval_seconds)
        self._updated_at = now

    def record_sync_failed(self, *, now: datetime | None = None) -> None:
        now = now or datetime.now(UTC)
        self._consecutive_failure_count += 1
        self._last_sync_completed_at = now
        self._last_sync_status = FeedSyncRunStatus.FAILED
        if self.is_syncable:
            self._next_sync_due_at = now + timedelta(seconds=self._schedule.interval_seconds)
        self._updated_at = now

    # ── Domain events ────────────────────────────────────────────────────

    def collect_events(self) -> list[FeedDomainEvent]:
        events = list(self._events)
        self._events.clear()
        return events
