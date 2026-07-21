"""ReportInstance aggregate — a specific generation run and artifact."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from reporting.domain.events.reporting_events import (
    ReportGenerationCompleted,
    ReportGenerationFailed,
    ReportGenerationStarted,
)
from reporting.domain.exceptions.domain_exceptions import (
    InvalidReportTransition,
    TenantMismatch,
)
from reporting.domain.value_objects.enums import ReportStatus, ReportTrigger, ReportType

if TYPE_CHECKING:
    from datetime import datetime

    from reporting.domain.events.base import BaseDomainEvent
    from reporting.domain.value_objects.identifiers import (
        ReportInstanceId,
        ReportTemplateId,
        ScheduledReportId,
        TenantId,
    )


class ReportInstance:
    __slots__ = (
        "_pending_events",
        "artifact_ref",
        "completed_at",
        "content",
        "created_at",
        "error_reason",
        "generated_by",
        "instance_id",
        "narrative",
        "narrative_variant",
        "report_type",
        "schedule_id",
        "status",
        "template_id",
        "tenant_id",
        "trigger",
    )

    def __init__(
        self,
        instance_id: ReportInstanceId,
        tenant_id: TenantId,
        template_id: ReportTemplateId,
        report_type: ReportType,
        status: ReportStatus,
        trigger: ReportTrigger,
        generated_by: str,
        created_at: datetime,
        narrative: str = "",
        narrative_variant: str = "",
        content: dict[str, Any] | None = None,
        artifact_ref: str | None = None,
        error_reason: str | None = None,
        completed_at: datetime | None = None,
        schedule_id: ScheduledReportId | None = None,
    ) -> None:
        self.instance_id = instance_id
        self.tenant_id = tenant_id
        self.template_id = template_id
        self.report_type = report_type
        self.status = status
        self.trigger = trigger
        self.generated_by = generated_by
        self.created_at = created_at
        self.narrative = narrative
        self.narrative_variant = narrative_variant
        self.content = dict(content or {})
        self.artifact_ref = artifact_ref
        self.error_reason = error_reason
        self.completed_at = completed_at
        self.schedule_id = schedule_id
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    @classmethod
    def start(
        cls,
        instance_id: ReportInstanceId,
        tenant_id: TenantId,
        template_id: ReportTemplateId,
        report_type: ReportType,
        trigger: ReportTrigger,
        generated_by: str,
        created_at: datetime,
        *,
        schedule_id: ScheduledReportId | None = None,
    ) -> ReportInstance:
        instance = cls(
            instance_id,
            tenant_id,
            template_id,
            report_type,
            ReportStatus.GENERATING,
            trigger,
            generated_by,
            created_at,
            schedule_id=schedule_id,
        )
        instance._emit(
            ReportGenerationStarted(
                tenant_id=str(tenant_id),
                aggregate_id=str(instance_id),
                template_id=str(template_id),
                triggered_by=generated_by,
            )
        )
        return instance

    def complete(
        self,
        tenant_id: TenantId,
        *,
        narrative: str,
        narrative_variant: str,
        content: dict[str, Any],
        artifact_ref: str,
        at: datetime,
    ) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch on complete")
        if self.status not in {ReportStatus.PENDING, ReportStatus.GENERATING}:
            raise InvalidReportTransition(f"cannot complete from {self.status.value}")
        self.status = ReportStatus.COMPLETE
        self.narrative = narrative
        self.narrative_variant = narrative_variant
        self.content = dict(content)
        self.artifact_ref = artifact_ref
        self.completed_at = at
        self._emit(
            ReportGenerationCompleted(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.instance_id),
                template_id=str(self.template_id),
                artifact_ref=artifact_ref,
            )
        )

    def fail(self, tenant_id: TenantId, *, error_reason: str, at: datetime) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch on fail")
        if self.status == ReportStatus.COMPLETE:
            raise InvalidReportTransition("cannot fail a complete report")
        self.status = ReportStatus.FAILED
        self.error_reason = error_reason
        self.completed_at = at
        self._emit(
            ReportGenerationFailed(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.instance_id),
                error_reason=error_reason,
            )
        )
