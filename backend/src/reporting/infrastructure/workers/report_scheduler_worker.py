"""ReportSchedulerWorker — due schedules only; idempotent via last_run_at."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from reporting.application.services.reporting_application_service import (
        ReportingApplicationService,
    )

logger = structlog.get_logger(__name__)


class ReportSchedulerWorker:
    def __init__(self, app: ReportingApplicationService) -> None:
        self._app = app
        self.runs = 0
        self.processed = 0

    async def tick(self, now: datetime | None = None) -> int:
        at = now or datetime.now(UTC)
        count = await self._app.process_due_schedules(at)
        self.runs += 1
        self.processed += count
        logger.info("reporting.scheduler_tick", processed=count, at=at.isoformat())
        return count
