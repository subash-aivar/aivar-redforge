"""In-memory lessons learned repositories."""

from __future__ import annotations

from lessons_learned.domain.aggregates.lessons_learned import LessonsLearned
from lessons_learned.domain.aggregates.post_incident_report import PostIncidentReport
from lessons_learned.domain.value_objects.identifiers import (
    LessonsLearnedId,
    PostIncidentReportId,
    TenantId,
)


class InMemoryLessonsLearnedRepository:
    def __init__(self) -> None:
        self._by_id: dict[str, dict[str, LessonsLearned]] = {}
        self._by_incident: dict[str, dict[str, str]] = {}

    async def find_by_id(
        self, tenant_id: TenantId, ll_id: LessonsLearnedId
    ) -> LessonsLearned | None:
        return self._by_id.get(str(tenant_id), {}).get(str(ll_id))

    async def find_by_incident(
        self, tenant_id: TenantId, incident_id: str
    ) -> LessonsLearned | None:
        ll_id = self._by_incident.get(str(tenant_id), {}).get(incident_id)
        if ll_id is None:
            return None
        return self._by_id.get(str(tenant_id), {}).get(ll_id)

    async def save(self, tenant_id: TenantId, ll: LessonsLearned) -> None:
        self._by_id.setdefault(str(tenant_id), {})[str(ll.ll_id)] = ll
        self._by_incident.setdefault(str(tenant_id), {})[ll.incident_id] = str(ll.ll_id)


class InMemoryPostIncidentReportRepository:
    def __init__(self) -> None:
        self._items: dict[str, dict[str, PostIncidentReport]] = {}

    async def find_by_id(
        self, tenant_id: TenantId, report_id: PostIncidentReportId
    ) -> PostIncidentReport | None:
        return self._items.get(str(tenant_id), {}).get(str(report_id))

    async def find_by_incident(
        self, tenant_id: TenantId, incident_id: str
    ) -> list[PostIncidentReport]:
        return [
            r for r in self._items.get(str(tenant_id), {}).values() if r.incident_id == incident_id
        ]

    async def save(self, tenant_id: TenantId, report: PostIncidentReport) -> None:
        self._items.setdefault(str(tenant_id), {})[str(report.report_id)] = report
