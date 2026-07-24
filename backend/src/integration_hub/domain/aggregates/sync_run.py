"""SyncRun entity — one record per discovery/sync execution against a
connector, tracked for audit and history display."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from integration_hub.domain.value_objects.discovery import SyncMode, SyncRunStatus
from integration_hub.domain.value_objects.identifiers import ConnectorId, EntityId


class SyncRun:
    __slots__ = (
        "cancelled",
        "completed_at",
        "connector_id",
        "cursor",
        "error",
        "items_created",
        "items_deleted",
        "items_discovered",
        "items_updated",
        "mode",
        "pages_processed",
        "started_at",
        "status",
        "sync_run_id",
        "tenant_id",
    )

    def __init__(
        self,
        sync_run_id: UUID,
        tenant_id: EntityId,
        connector_id: ConnectorId,
        mode: SyncMode,
        status: SyncRunStatus,
        *,
        started_at: datetime,
        completed_at: datetime | None = None,
        items_discovered: int = 0,
        items_created: int = 0,
        items_updated: int = 0,
        items_deleted: int = 0,
        error: str | None = None,
        cancelled: bool = False,
        cursor: str | None = None,
        pages_processed: int = 0,
    ) -> None:
        self.sync_run_id = sync_run_id
        self.tenant_id = tenant_id
        self.connector_id = connector_id
        self.mode = mode
        self.status = status
        self.started_at = started_at
        self.completed_at = completed_at
        self.items_discovered = items_discovered
        self.items_created = items_created
        self.items_updated = items_updated
        self.items_deleted = items_deleted
        self.error = error
        self.cancelled = cancelled
        # Checkpoint state (Phase 2C): the continuation cursor for the next
        # page to fetch, and how many pages have been successfully
        # processed and persisted so far. Both are persisted on every
        # `save()` between pages (see AssetDiscoveryApplicationService.
        # run_discovery), so a crash mid-run can resume from the last
        # completed page instead of restarting from zero.
        self.cursor = cursor
        self.pages_processed = pages_processed

    @classmethod
    def start(cls, tenant_id: EntityId, connector_id: ConnectorId, mode: SyncMode) -> SyncRun:
        return cls(
            uuid4(),
            tenant_id,
            connector_id,
            mode,
            SyncRunStatus.RUNNING,
            started_at=datetime.now(UTC),
        )

    def request_cancel(self) -> None:
        self.cancelled = True

    def record_page(
        self, *, cursor: str | None, discovered: int, created: int, updated: int
    ) -> None:
        """Checkpoint after one successfully processed+persisted page:
        advance the cursor and running counters. Called between pages so
        the persisted state always reflects the last completed page, not
        the whole run."""
        self.cursor = cursor
        self.pages_processed += 1
        self.items_discovered += discovered
        self.items_created += created
        self.items_updated += updated

    def complete(
        self, *, discovered: int, created: int, updated: int, deleted: int
    ) -> None:
        self.status = (
            SyncRunStatus.CANCELLED if self.cancelled else SyncRunStatus.COMPLETED
        )
        self.completed_at = datetime.now(UTC)
        self.items_discovered = discovered
        self.items_created = created
        self.items_updated = updated
        self.items_deleted = deleted

    def mark_partial(self, error: str | None = None) -> None:
        """The run hit the per-invocation max-pages safety limit (or a page
        fetch failed after at least one page had already succeeded), with
        `has_more` still true or the remaining pages unknown. The run's
        checkpoint (`cursor`/`pages_processed`/counters) is left intact so
        a subsequent invocation resumes rather than restarting from zero —
        distinct from `fail()`, which is for a hard failure on the very
        first page with nothing yet persisted."""
        self.status = SyncRunStatus.PARTIAL
        self.completed_at = datetime.now(UTC)
        self.error = error

    def fail(self, error: str) -> None:
        self.status = SyncRunStatus.FAILED
        self.completed_at = datetime.now(UTC)
        self.error = error
