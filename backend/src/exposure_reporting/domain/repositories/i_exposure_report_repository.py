"""IExposureReportRepository."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from exposure_reporting.domain.aggregates.exposure_report import ExposureReport
    from exposure_reporting.domain.value_objects.identifiers import (
        ExposureReportId,
        TenantId,
    )


class IExposureReportRepository(ABC):
    @abstractmethod
    async def get(
        self, tenant_id: TenantId, report_id: ExposureReportId
    ) -> ExposureReport | None: ...

    @abstractmethod
    async def save(self, tenant_id: TenantId, report: ExposureReport) -> None: ...

    @abstractmethod
    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        report_type: str | None = None,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> list[ExposureReport]: ...
