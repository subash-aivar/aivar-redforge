"""IReportTemplateRepository — platform templates are tenant-unscoped."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from reporting.domain.aggregates.report_template import ReportTemplate
    from reporting.domain.value_objects.enums import ReportType
    from reporting.domain.value_objects.identifiers import ReportTemplateId, TenantId


class IReportTemplateRepository(ABC):
    @abstractmethod
    async def find_by_id(self, template_id: ReportTemplateId) -> ReportTemplate | None: ...

    @abstractmethod
    async def find_by_type_for_tenant(
        self, tenant_id: TenantId, report_type: ReportType
    ) -> ReportTemplate | None: ...

    @abstractmethod
    async def save(self, template: ReportTemplate) -> None: ...
