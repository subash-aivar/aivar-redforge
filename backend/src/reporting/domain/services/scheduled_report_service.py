"""ScheduledReportService — schedule management and due-run claiming."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from reporting.domain.aggregates.scheduled_report import ScheduledReport
from reporting.domain.exceptions.domain_exceptions import TenantMismatch
from reporting.domain.value_objects.identifiers import ScheduledReportId

if TYPE_CHECKING:
    from datetime import datetime

    from reporting.domain.value_objects.identifiers import ReportTemplateId, TenantId


class ScheduledReportService:
    def create(
        self,
        *,
        tenant_id: TenantId,
        template_id: ReportTemplateId,
        schedule_cron: str,
        cadence_minutes: int,
        next_run_at: datetime,
        parameters: dict[str, Any],
        recipients: list[str],
        created_by: str,
        created_at: datetime,
    ) -> ScheduledReport:
        return ScheduledReport.create(
            ScheduledReportId.generate(),
            tenant_id,
            template_id,
            schedule_cron,
            cadence_minutes,
            next_run_at,
            parameters,
            recipients,
            created_by,
            created_at,
        )

    def claim_due_run(self, schedule: ScheduledReport, tenant_id: TenantId, now: datetime) -> bool:
        if schedule.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch on claim_due_run")
        return schedule.claim_run(tenant_id, now)
