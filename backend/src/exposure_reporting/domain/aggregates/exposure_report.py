"""ExposureReport aggregate — Finalization Phase 5."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from exposure_reporting.domain.events.reporting_events import (
    ExposureReportDelivered,
    ExposureReportGenerated,
)
from exposure_reporting.domain.exceptions.domain_exceptions import (
    InvalidReportTransition,
    TenantMismatch,
)
from exposure_reporting.domain.value_objects.enums import ReportStatus, ReportType

if TYPE_CHECKING:
    from datetime import datetime

    from exposure_reporting.domain.events.base import BaseDomainEvent
    from exposure_reporting.domain.value_objects.identifiers import (
        ExposureReportId,
        TenantId,
    )


class ExposureReport:
    __slots__ = (
        "_pending_events",
        "content",
        "delivered_at",
        "generated_at",
        "generated_by",
        "narrative",
        "report_id",
        "report_type",
        "status",
        "template_id",
        "tenant_id",
        "time_range_end",
        "time_range_start",
    )

    def __init__(
        self,
        report_id: ExposureReportId,
        tenant_id: TenantId,
        report_type: ReportType,
        status: ReportStatus,
        template_id: str,
        narrative: str,
        content: dict[str, Any],
        generated_by: str,
        generated_at: datetime,
        time_range_start: datetime | None = None,
        time_range_end: datetime | None = None,
        delivered_at: datetime | None = None,
    ) -> None:
        self.report_id = report_id
        self.tenant_id = tenant_id
        self.report_type = report_type
        self.status = status
        self.template_id = template_id
        self.narrative = narrative
        self.content = dict(content)
        self.generated_by = generated_by
        self.generated_at = generated_at
        self.time_range_start = time_range_start
        self.time_range_end = time_range_end
        self.delivered_at = delivered_at
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
        report_id: ExposureReportId,
        tenant_id: TenantId,
        report_type: ReportType,
        template_id: str,
        narrative: str,
        content: dict[str, Any],
        generated_by: str,
        generated_at: datetime,
        *,
        time_range_start: datetime | None = None,
        time_range_end: datetime | None = None,
    ) -> ExposureReport:
        report = cls(
            report_id,
            tenant_id,
            report_type,
            ReportStatus.GENERATED,
            template_id,
            narrative,
            content,
            generated_by,
            generated_at,
            time_range_start=time_range_start,
            time_range_end=time_range_end,
        )
        report._emit(
            ExposureReportGenerated(
                tenant_id=str(tenant_id),
                aggregate_id=str(report_id),
                report_type=report_type.value,
                template_id=template_id,
            )
        )
        return report

    def mark_delivered(self, tenant_id: TenantId, channel: str, at: datetime) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch on deliver")
        if self.status == ReportStatus.DELIVERED:
            raise InvalidReportTransition("report already delivered")
        self.status = ReportStatus.DELIVERED
        self.delivered_at = at
        self._emit(
            ExposureReportDelivered(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.report_id),
                delivery_channel=channel,
            )
        )
