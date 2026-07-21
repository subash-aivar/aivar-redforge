"""ScheduledReport aggregate — recurring generation configuration."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from reporting.domain.events.reporting_events import ScheduledReportCreated
from reporting.domain.exceptions.domain_exceptions import (
    InvalidScheduleTransition,
    TenantMismatch,
)
from reporting.domain.value_objects.enums import ScheduleStatus

if TYPE_CHECKING:
    from datetime import datetime

    from reporting.domain.events.base import BaseDomainEvent
    from reporting.domain.value_objects.identifiers import (
        ReportTemplateId,
        ScheduledReportId,
        TenantId,
    )


class ScheduledReport:
    __slots__ = (
        "_pending_events",
        "cadence_minutes",
        "created_at",
        "created_by",
        "last_run_at",
        "next_run_at",
        "parameters",
        "recipients",
        "schedule_cron",
        "schedule_id",
        "status",
        "template_id",
        "tenant_id",
    )

    def __init__(
        self,
        schedule_id: ScheduledReportId,
        tenant_id: TenantId,
        template_id: ReportTemplateId,
        schedule_cron: str,
        cadence_minutes: int,
        next_run_at: datetime,
        status: ScheduleStatus,
        parameters: dict[str, Any],
        recipients: list[str],
        created_by: str,
        created_at: datetime,
        last_run_at: datetime | None = None,
    ) -> None:
        self.schedule_id = schedule_id
        self.tenant_id = tenant_id
        self.template_id = template_id
        self.schedule_cron = schedule_cron
        self.cadence_minutes = cadence_minutes
        self.next_run_at = next_run_at
        self.status = status
        self.parameters = dict(parameters)
        self.recipients = list(recipients)
        self.created_by = created_by
        self.created_at = created_at
        self.last_run_at = last_run_at
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    @classmethod
    def create(
        cls,
        schedule_id: ScheduledReportId,
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
        schedule = cls(
            schedule_id,
            tenant_id,
            template_id,
            schedule_cron,
            cadence_minutes,
            next_run_at,
            ScheduleStatus.ACTIVE,
            parameters,
            recipients,
            created_by,
            created_at,
        )
        schedule._emit(
            ScheduledReportCreated(
                tenant_id=str(tenant_id),
                aggregate_id=str(schedule_id),
                template_id=str(template_id),
                schedule=schedule_cron,
            )
        )
        return schedule

    def is_due(self, now: datetime) -> bool:
        return self.status == ScheduleStatus.ACTIVE and self.next_run_at <= now

    def claim_run(self, tenant_id: TenantId, now: datetime) -> bool:
        """Idempotent claim for a due slot. Advances next_run_at on success."""
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch on claim_run")
        if not self.is_due(now):
            return False
        if self.last_run_at is not None and self.last_run_at >= self.next_run_at:
            return False
        self.last_run_at = now
        self.next_run_at = now + timedelta(minutes=max(1, self.cadence_minutes))
        return True

    def pause(self, tenant_id: TenantId) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch on pause")
        if self.status == ScheduleStatus.PAUSED:
            raise InvalidScheduleTransition("schedule already paused")
        self.status = ScheduleStatus.PAUSED

    def mark_error(self, tenant_id: TenantId) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch on mark_error")
        self.status = ScheduleStatus.ERROR
