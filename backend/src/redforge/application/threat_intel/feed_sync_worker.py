"""Feed Sync Scheduler Worker — M22 Phase 2 (Feed Synchronization
Foundation).

Same asyncio poll-loop + start()/stop()/stats() lifecycle as
`BehaviorDetectionWorker` (M20) / `DDoSDetectionWorker` (M19). Each
cycle: acquire a single global advisory lock (so at most one running
application process polls at a time — a second process's cycle
short-circuits immediately, exactly like
`BehaviorDetectionWorker._run_cycle`'s org-listing lock), list ACTIVE
feeds whose `next_sync_due_at` has arrived, and trigger a SCHEDULED
sync for each via `FeedSyncOrchestrationService` — which itself takes
a second, per-feed advisory lock before doing anything, so this
worker's own cycle-level lock is purely a "don't double-poll"
optimization, never the sole concurrency guard.

Each per-feed trigger is fully isolated: one feed's
`FeedSyncAlreadyRunningError`, `UnknownFeedConnectorError`, or any
connector failure never aborts the cycle for the remaining due feeds.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import text

from redforge.domain.threat_intel.feed_value_objects import FeedSyncTrigger

if TYPE_CHECKING:
    from redforge.application.threat_intel.feed_sync_orchestration_service import (
        FeedSyncOrchestrationService,
    )

log = logging.getLogger(__name__)

DEFAULT_POLL_SECONDS = 60
MAX_FEEDS_PER_CYCLE = 25
_SCHEDULER_LOCK_HASH = 0x46454544_53595943  # "FEED" "SYNC" as ASCII, truncated to fit int8

# Platform-level actor identity for scheduler-triggered syncs — the
# audit trail must always name a concrete actor, and no human triggers
# a SCHEDULED run, mirroring `system` actor conventions used elsewhere
# for background-worker-initiated audit entries.
_SCHEDULER_ACTOR_ID = "system:feed_sync_scheduler"


class FeedSyncSchedulerWorker:
    """Background asyncio worker that triggers scheduled synchronization
    for every due, ACTIVE `Feed`."""

    def __init__(
        self,
        session_factory: Any,
        orchestration_service: FeedSyncOrchestrationService,
        poll_seconds: int = DEFAULT_POLL_SECONDS,
    ) -> None:
        self._session_factory = session_factory
        self._orchestration_service = orchestration_service
        self._poll_seconds = poll_seconds
        self._task: asyncio.Task[None] | None = None
        self._running = False
        self._stats: dict[str, Any] = {
            "cycles": 0,
            "feeds_triggered": 0,
            "feeds_succeeded": 0,
            "feeds_failed": 0,
            "errors": 0,
            "started_at": None,
            "last_cycle_at": None,
        }

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._stats["started_at"] = datetime.now(UTC).isoformat()
        self._task = asyncio.create_task(self._loop(), name="feed_sync_scheduler_worker")
        log.info("FeedSyncSchedulerWorker started (poll_seconds=%d)", self._poll_seconds)

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        log.info("FeedSyncSchedulerWorker stopped — stats: %s", self._stats)

    def stats(self) -> dict[str, Any]:
        return dict(self._stats)

    async def _loop(self) -> None:
        while self._running:
            try:
                await self._run_cycle()
            except Exception:
                log.exception("FeedSyncSchedulerWorker: unhandled exception in cycle")
                self._stats["errors"] += 1
            await asyncio.sleep(self._poll_seconds)

    async def _run_cycle(self) -> None:
        from redforge.infrastructure.database.repositories.feed_sync_repository import (
            SqlAlchemyFeedRepository,
        )

        self._stats["cycles"] += 1
        self._stats["last_cycle_at"] = datetime.now(UTC).isoformat()

        async with self._session_factory() as session, session.begin():
            lock_result = await session.execute(
                text("SELECT pg_try_advisory_xact_lock(:h)"), {"h": _SCHEDULER_LOCK_HASH}
            )
            if not lock_result.scalar():
                log.debug("FeedSyncSchedulerWorker: lock not acquired, skipping cycle")
                return

            feed_repo = SqlAlchemyFeedRepository(session)
            due_feeds = await feed_repo.list_due_for_sync(
                now=datetime.now(UTC), limit=MAX_FEEDS_PER_CYCLE
            )
            feed_ids = [feed.id for feed in due_feeds]

        for feed_id in feed_ids:
            self._stats["feeds_triggered"] += 1
            try:
                await self._orchestration_service.trigger_sync(
                    feed_id=feed_id,
                    trigger=FeedSyncTrigger.SCHEDULED,
                    actor_id=_SCHEDULER_ACTOR_ID,
                )
                self._stats["feeds_succeeded"] += 1
            except Exception:
                log.exception(
                    "FeedSyncSchedulerWorker: sync trigger failed for feed_id=%s", feed_id
                )
                self._stats["feeds_failed"] += 1
