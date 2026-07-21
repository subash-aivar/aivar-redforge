from __future__ import annotations

from datetime import datetime
from typing import Any

from lessons_learned.domain.events.lessons_events import (
    PostIncidentReportExported,
    PostIncidentReportGenerated,
)
from lessons_learned.domain.exceptions.domain_exceptions import InvalidLLTransition, TenantMismatch
from lessons_learned.domain.value_objects.enums import PostIncidentReportStatus, ReportFormat
from lessons_learned.domain.value_objects.identifiers import (
    LessonsLearnedId,
    PostIncidentReportId,
    TenantId,
)


class PostIncidentReport:
    def __init__(
        self,
        report_id: PostIncidentReportId,
        tenant_id: TenantId,
        incident_id: str,
        lessons_learned_id: LessonsLearnedId,
        fmt: ReportFormat,
        status: PostIncidentReportStatus,
    ) -> None:
        self.report_id = report_id
        self.tenant_id = tenant_id
        self.incident_id = incident_id
        self.lessons_learned_id = lessons_learned_id
        self.format = fmt
        self.status = status
        self.artifact_ref: str | None = None
        self.artifact_bytes: bytes = b""
        self.generated_at: datetime | None = None
        self.exported_at: datetime | None = None
        self.exported_to: str | None = None
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        ev = list(self._pending_events)
        self._pending_events.clear()
        return ev

    def complete(
        self, tenant_id: TenantId, artifact_ref: str, payload: bytes, at: datetime
    ) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        if self.status != PostIncidentReportStatus.GENERATING:
            raise InvalidLLTransition()
        self.status = PostIncidentReportStatus.COMPLETE
        self.artifact_ref = artifact_ref
        self.artifact_bytes = payload
        self.generated_at = at
        self._pending_events.append(
            PostIncidentReportGenerated(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.report_id),
                report_id=str(self.report_id),
                ll_id=str(self.lessons_learned_id),
                incident_id=self.incident_id,
                format=self.format.value,
                generated_at=at.isoformat(),
            )
        )

    def export(self, tenant_id: TenantId, destination: str, at: datetime) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        if self.status != PostIncidentReportStatus.COMPLETE:
            raise InvalidLLTransition()
        self.status = PostIncidentReportStatus.EXPORTED
        self.exported_to = destination
        self.exported_at = at
        self._pending_events.append(
            PostIncidentReportExported(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.report_id),
                report_id=str(self.report_id),
                exported_to=destination,
                exported_at=at.isoformat(),
            )
        )
