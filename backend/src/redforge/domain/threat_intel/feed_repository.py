"""Repository protocols for the Feed Synchronization Foundation
sub-context — M22 Phase 2.

Mirrors the exact `@runtime_checkable Protocol` shape of
`reference_data_repository.py` (M22 Phase 1) and
`domain/investigations/repository.py` (M21). All I/O goes through
these ports; `infrastructure.database.repositories.feed_sync` provides
the concrete PostgreSQL implementations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from datetime import datetime

    from redforge.domain.threat_intel.feed_entity import Feed
    from redforge.domain.threat_intel.feed_sync_run_entity import FeedSyncRun
    from redforge.domain.threat_intel.feed_value_objects import FeedSourceKind, FeedStatus
    from redforge.domain.threat_intel.reference_data_value_objects import IngestionScope


@runtime_checkable
class FeedRepository(Protocol):
    """Port for `Feed` aggregate persistence (the `feeds` table)."""

    async def add(self, feed: Feed) -> Feed:
        """Insert a newly-registered feed. Raises `DuplicateFeedKeyError`
        (mapped from the database's partial unique constraint on
        `(scope, organization_id, feed_key)`) if one already exists in
        this scope."""
        ...

    async def update(self, feed: Feed) -> Feed:
        """Persist mutations to an existing feed (lifecycle transitions,
        configuration updates, sync bookkeeping). Never creates a new
        row."""
        ...

    async def get_by_id(self, feed_id: str) -> Feed | None:
        ...

    async def find_by_key(
        self,
        feed_key: str,
        *,
        scope: IngestionScope,
        organization_id: str | None = None,
    ) -> Feed | None:
        ...

    async def list_all(
        self,
        *,
        scope: IngestionScope | None = None,
        organization_id: str | None = None,
        status: FeedStatus | None = None,
        source_kind: FeedSourceKind | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[Feed]:
        ...

    async def count(
        self,
        *,
        scope: IngestionScope | None = None,
        organization_id: str | None = None,
        status: FeedStatus | None = None,
    ) -> int:
        ...

    async def list_due_for_sync(self, *, now: datetime, limit: int = 50) -> list[Feed]:
        """ACTIVE feeds whose `next_sync_due_at` has arrived, ordered by
        how overdue they are (most overdue first). Used exclusively by
        `FeedSyncSchedulerWorker` — never by the admin API, which
        triggers syncs directly by `feed_id`."""
        ...


@runtime_checkable
class FeedSyncRunRepository(Protocol):
    """Port for `FeedSyncRun` execution-history persistence (the
    `feed_sync_runs` table)."""

    async def add(self, run: FeedSyncRun) -> FeedSyncRun:
        """Insert a newly-started run. Raises `FeedSyncAlreadyRunningError`
        (mapped from the database's partial unique index enforcing at
        most one non-terminal run per `feed_id`) if one is already
        PENDING/RUNNING for this feed."""
        ...

    async def update(self, run: FeedSyncRun) -> FeedSyncRun:
        """Persist a finalized (SUCCEEDED/FAILED) run. Never creates a
        new row."""
        ...

    async def get_by_id(self, run_id: str) -> FeedSyncRun | None:
        ...

    async def get_active_run_for_feed(self, feed_id: str) -> FeedSyncRun | None:
        """The single non-terminal (PENDING/RUNNING) run for this feed,
        if any — an O(1) existence check backed by the same partial
        unique index `add()` relies on."""
        ...

    async def list_by_feed(
        self, feed_id: str, *, limit: int = 50, offset: int = 0
    ) -> list[FeedSyncRun]:
        """Most recent runs first."""
        ...

    async def count_by_feed(self, feed_id: str) -> int:
        ...
