"""In-memory repositories for reporting Phase 2."""

from __future__ import annotations

from typing import TYPE_CHECKING

from reporting.domain.repositories.i_report_instance_repository import (
    IReportInstanceRepository,
)
from reporting.domain.repositories.i_report_template_repository import (
    IReportTemplateRepository,
)
from reporting.domain.repositories.i_scheduled_report_repository import (
    IScheduledReportRepository,
)
from reporting.domain.value_objects.enums import ScheduleStatus

if TYPE_CHECKING:
    from datetime import datetime

    from reporting.domain.aggregates.report_instance import ReportInstance
    from reporting.domain.aggregates.report_template import ReportTemplate
    from reporting.domain.aggregates.scheduled_report import ScheduledReport
    from reporting.domain.value_objects.enums import ReportType
    from reporting.domain.value_objects.identifiers import (
        ReportInstanceId,
        ReportTemplateId,
        ScheduledReportId,
        TenantId,
    )


class InMemoryReportTemplateRepository(IReportTemplateRepository):
    def __init__(self) -> None:
        self._by_id: dict[str, ReportTemplate] = {}
        self._by_type: dict[str, str] = {}

    async def find_by_id(self, template_id: ReportTemplateId) -> ReportTemplate | None:
        return self._by_id.get(str(template_id))

    async def find_by_type_for_tenant(
        self, tenant_id: TenantId, report_type: ReportType
    ) -> ReportTemplate | None:
        del tenant_id  # platform templates are tenant-unscoped in Phase 2
        mid = self._by_type.get(report_type.value)
        if mid is None:
            return None
        return self._by_id.get(mid)

    async def save(self, template: ReportTemplate) -> None:
        self._by_id[str(template.template_id)] = template
        self._by_type[template.report_type.value] = str(template.template_id)


class InMemoryScheduledReportRepository(IScheduledReportRepository):
    def __init__(self) -> None:
        self._rows: dict[str, dict[str, ScheduledReport]] = {}

    async def find_by_id(
        self, tenant_id: TenantId, schedule_id: ScheduledReportId
    ) -> ScheduledReport | None:
        return self._rows.get(str(tenant_id), {}).get(str(schedule_id))

    async def find_due(self, now: datetime) -> list[ScheduledReport]:
        out: list[ScheduledReport] = []
        for bucket in self._rows.values():
            for schedule in bucket.values():
                if schedule.status == ScheduleStatus.ACTIVE and schedule.next_run_at <= now:
                    out.append(schedule)
        return out

    async def save(self, tenant_id: TenantId, schedule: ScheduledReport) -> None:
        if schedule.tenant_id.value != tenant_id.value:
            raise ValueError("tenant mismatch on save")
        self._rows.setdefault(str(tenant_id), {})[str(schedule.schedule_id)] = schedule

    async def list_by_tenant(self, tenant_id: TenantId) -> list[ScheduledReport]:
        return list(self._rows.get(str(tenant_id), {}).values())


class InMemoryReportInstanceRepository(IReportInstanceRepository):
    def __init__(self) -> None:
        self._rows: dict[str, dict[str, ReportInstance]] = {}

    async def find_by_id(
        self, tenant_id: TenantId, instance_id: ReportInstanceId
    ) -> ReportInstance | None:
        return self._rows.get(str(tenant_id), {}).get(str(instance_id))

    async def find_by_template(
        self,
        tenant_id: TenantId,
        template_id: ReportTemplateId,
        *,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> list[ReportInstance]:
        return await self.list_by_tenant(
            tenant_id, template_id=template_id, from_dt=from_dt, to_dt=to_dt
        )

    async def save(self, tenant_id: TenantId, instance: ReportInstance) -> None:
        if instance.tenant_id.value != tenant_id.value:
            raise ValueError("tenant mismatch on save")
        self._rows.setdefault(str(tenant_id), {})[str(instance.instance_id)] = instance

    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        template_id: ReportTemplateId | None = None,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> list[ReportInstance]:
        rows = list(self._rows.get(str(tenant_id), {}).values())
        if template_id is not None:
            rows = [r for r in rows if str(r.template_id) == str(template_id)]
        if from_dt is not None:
            rows = [r for r in rows if r.created_at >= from_dt]
        if to_dt is not None:
            rows = [r for r in rows if r.created_at <= to_dt]
        return sorted(rows, key=lambda r: r.created_at, reverse=True)
