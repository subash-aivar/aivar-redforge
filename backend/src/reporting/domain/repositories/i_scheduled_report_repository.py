"""IScheduledReportRepository — tenant-scoped; find_due is scheduler-only."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from reporting.domain.aggregates.scheduled_report import ScheduledReport
    from reporting.domain.value_objects.identifiers import ScheduledReportId, TenantId


class IScheduledReportRepository(ABC):
    @abstractmethod
    async def find_by_id(
        self, tenant_id: TenantId, schedule_id: ScheduledReportId
    ) -> ScheduledReport | None: ...

    @abstractmethod
    async def find_due(self, now: datetime) -> list[ScheduledReport]: ...

    @abstractmethod
    async def save(self, tenant_id: TenantId, schedule: ScheduledReport) -> None: ...

    @abstractmethod
    async def list_by_tenant(self, tenant_id: TenantId) -> list[ScheduledReport]: ...
