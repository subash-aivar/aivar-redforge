"""DDoS Detection Background Worker — M19.

Follows the ContinuousValidationSchedulerWorker pattern established in
M15/M16/M17/M18: asyncio poll loop, bounded batch, exception isolation
per resource, start()/stop()/stats() lifecycle.

Clock resolution: window_seconds (default 60s). The worker computes
the PREVIOUS completed window to ensure all telemetry is flushed before
aggregation. It never re-runs a window that already has a persisted
observation (idempotency guaranteed by the upsert ON CONFLICT constraint).

Resource iteration:
  Each poll cycle lists all enabled protected resources with enabled
  policies for the organization. The batch is bounded by MAX_RESOURCES_PER_CYCLE
  to prevent long cycles from blocking the event loop.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

log = logging.getLogger(__name__)

MAX_RESOURCES_PER_CYCLE = 100
DEFAULT_POLL_SECONDS = 60


class DDoSDetectionWorker:
    """Background asyncio worker that runs DDoS detection cycles.

    One instance per application process. The worker iterates all
    enabled resources every poll_seconds and runs one detection cycle
    per resource per completed time window.
    """

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
            "resources_processed": 0,
            "detections_fired": 0,
            "incidents_opened": 0,
            "incidents_resolved": 0,
            "errors": 0,
            "started_at": None,
            "last_cycle_at": None,
        }

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._stats["started_at"] = datetime.now(UTC).isoformat()
        self._task = asyncio.create_task(self._loop(), name="ddos_detection_worker")
        log.info("DDoSDetectionWorker started (poll_seconds=%d)", self._poll_seconds)

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        log.info("DDoSDetectionWorker stopped — stats: %s", self._stats)

    def stats(self) -> dict[str, Any]:
        return dict(self._stats)

    async def _loop(self) -> None:
        while self._running:
            try:
                await self._run_cycle()
            except Exception:
                log.exception("DDoSDetectionWorker: unhandled exception in cycle")
                self._stats["errors"] += 1
            await asyncio.sleep(self._poll_seconds)

    async def _run_cycle(self) -> None:
        from redforge.application.ddos.detection_service import DDoSDetectionService
        from redforge.infrastructure.database.repositories.ddos.resource_repository import (
            SqlAlchemyDetectionPolicyRepository,
            SqlAlchemyProtectedResourceRepository,
        )

        now = datetime.now(UTC)
        # Compute the previous complete window
        window_seconds = self._poll_seconds
        window_end = now.replace(second=0, microsecond=0)
        window_start = window_end - timedelta(seconds=window_seconds)

        self._stats["cycles"] += 1
        self._stats["last_cycle_at"] = now.isoformat()

        async with self._session_factory() as session, session.begin():
                SqlAlchemyProtectedResourceRepository(session)
                policy_repo = SqlAlchemyDetectionPolicyRepository(session)

                # Iterate organizations is not feasible without a tenant list;
                # the worker is keyed by session_factory which is org-scoped
                # in production (one factory per org, injected at startup).
                # For the platform-level shared worker, organizations are derived
                # from the distinct org IDs with enabled resources.
                from sqlalchemy import select

                from redforge.infrastructure.database.models.ddos import (
                    DDoSDetectionPolicyModel,
                    DDoSProtectedResourceModel,
                )

                stmt = (
                    select(
                        DDoSProtectedResourceModel.organization_id,
                        DDoSProtectedResourceModel.id.label("resource_id"),
                        DDoSProtectedResourceModel.name.label("resource_name"),
                    )
                    .join(
                        DDoSDetectionPolicyModel,
                        (DDoSDetectionPolicyModel.resource_id == DDoSProtectedResourceModel.id)
                        & (
                            DDoSDetectionPolicyModel.organization_id
                            == DDoSProtectedResourceModel.organization_id
                        )
                        & DDoSDetectionPolicyModel.enabled.is_(True),
                    )
                    .where(DDoSProtectedResourceModel.monitoring_enabled.is_(True))
                    .limit(MAX_RESOURCES_PER_CYCLE)
                )
                rows = (await session.execute(stmt)).all()

                detection_svc = DDoSDetectionService(session)

                for row in rows:
                    org_id = row.organization_id
                    resource_id = row.resource_id
                    resource_name = row.resource_name

                    policy = await policy_repo.get_by_resource(org_id, resource_id)
                    if policy is None:
                        continue

                    try:
                        cycle_result = await detection_svc.run_cycle(
                            organization_id=org_id,
                            resource_id=resource_id,
                            resource_name=resource_name,
                            window_start=window_start,
                            window_end=window_end,
                            window_seconds=policy.window_seconds,
                            quiet_period_windows=policy.quiet_period_windows,
                            static_bps_threshold=policy.static_bps_threshold,
                            static_pps_threshold=policy.static_pps_threshold,
                            static_fps_threshold=policy.static_fps_threshold,
                            mitigation_mode=policy.mitigation_mode,
                        )
                        self._stats["resources_processed"] += 1
                        if cycle_result.detection_fired:
                            self._stats["detections_fired"] += 1
                            if cycle_result.incident_id:
                                self._stats["incidents_opened"] += 1
                        if cycle_result.quiet_window_resolved:
                            self._stats["incidents_resolved"] += 1
                    except Exception:
                        log.exception(
                            "DDoSDetectionWorker: error processing resource %s/%s",
                            org_id,
                            resource_id,
                        )
                        self._stats["errors"] += 1
                        # Continue — don't let one resource failure abort the batch
