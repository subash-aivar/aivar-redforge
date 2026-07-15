"""Behavioral Security Detection Background Worker — M20.

Follows the DDoSDetectionWorker pattern from M19: asyncio poll loop,
bounded batch, exception isolation, start()/stop()/stats() lifecycle.

Clock resolution: poll_seconds (default 300s = 5 minutes).
The worker computes the PREVIOUS completed window each cycle.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger(__name__)

MAX_ORGS_PER_CYCLE = 50
DEFAULT_POLL_SECONDS = 300  # 5-minute windows


class BehaviorDetectionWorker:
    """Background asyncio worker for behavioral anomaly detection."""

    def __init__(
        self,
        session_factory: Any,
        poll_seconds: int = DEFAULT_POLL_SECONDS,
    ) -> None:
        self._session_factory = session_factory
        self._poll_seconds = poll_seconds
        self._task: asyncio.Task[None] | None = None
        self._running = False
        self._stats: dict[str, Any] = {
            "cycles": 0,
            "orgs_processed": 0,
            "detections_fired": 0,
            "detections_opened": 0,
            "errors": 0,
            "started_at": None,
            "last_cycle_at": None,
        }

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._stats["started_at"] = datetime.now(UTC).isoformat()
        self._task = asyncio.create_task(self._loop(), name="behavior_detection_worker")
        log.info("BehaviorDetectionWorker started (poll_seconds=%d)", self._poll_seconds)

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        log.info("BehaviorDetectionWorker stopped — stats: %s", self._stats)

    def stats(self) -> dict[str, Any]:
        return dict(self._stats)

    async def _loop(self) -> None:
        while self._running:
            try:
                await self._run_cycle()
            except Exception:
                log.exception("BehaviorDetectionWorker: unhandled exception in cycle")
                self._stats["errors"] += 1
            await asyncio.sleep(self._poll_seconds)

    async def _run_cycle(self) -> None:
        from sqlalchemy import select, text

        from redforge.application.behavior.detection_service import BehaviorDetectionService
        from redforge.infrastructure.database.models.organization import OrganizationModel

        now = datetime.now(UTC)
        window_end = now.replace(second=0, microsecond=0)

        async with self._session_factory() as session, session.begin():
            # Advisory lock to prevent duplicate workers from processing the
            # same cycle concurrently. pg_try_advisory_xact_lock returns FALSE
            # if another session holds the lock — skip this cycle in that case.
            # Detection-level upserts are also race-safe via per-detection
            # advisory locks + partial unique index, so duplicate processing is
            # safe by construction even if the org-listing lock is not acquired.
            lock_hash = 0x42424242BEEF0001
            lock_result = await session.execute(
                text("SELECT pg_try_advisory_xact_lock(:h)"), {"h": lock_hash}
            )
            lock_acquired = lock_result.scalar()
            if not lock_acquired:
                log.debug("BehaviorDetectionWorker: lock not acquired, skipping cycle")
                return

            # List active organizations
            result = await session.execute(
                select(OrganizationModel.id).where(
                    OrganizationModel.status == "active"
                ).limit(MAX_ORGS_PER_CYCLE)
            )
            org_ids = [row[0] for row in result.all()]

        for org_id in org_ids:
            try:
                async with self._session_factory() as session, session.begin():
                    svc = BehaviorDetectionService(session)
                    cycle_stats = await svc.run_cycle(
                        organization_id=org_id,
                        window_end=window_end,
                        window_seconds=self._poll_seconds,
                    )
                    self._stats["detections_fired"] += cycle_stats.get("detections_fired", 0)
                    self._stats["detections_opened"] += cycle_stats.get("detections_opened", 0)
                    self._stats["orgs_processed"] += 1
            except Exception:
                log.exception(
                    "BehaviorDetectionWorker: org cycle error org=%s", org_id
                )
                self._stats["errors"] += 1

        self._stats["cycles"] += 1
        self._stats["last_cycle_at"] = now.isoformat()
