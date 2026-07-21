"""IReportInstanceRepository — tenant-scoped."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from reporting.domain.aggregates.report_instance import ReportInstance
    from reporting.domain.value_objects.identifiers import (
        ReportInstanceId,
        ReportTemplateId,
        TenantId,
    )


class IReportInstanceRepository(ABC):
    @abstractmethod
    async def find_by_id(
        self, tenant_id: TenantId, instance_id: ReportInstanceId
    ) -> ReportInstance | None: ...

    @abstractmethod
    async def find_by_template(
        self,
        tenant_id: TenantId,
        template_id: ReportTemplateId,
        *,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> list[ReportInstance]: ...

    @abstractmethod
    async def save(self, tenant_id: TenantId, instance: ReportInstance) -> None: ...

    @abstractmethod
    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        template_id: ReportTemplateId | None = None,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> list[ReportInstance]: ...
