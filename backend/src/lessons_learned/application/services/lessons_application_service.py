from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from lessons_learned.application._auth import require_at_least
from lessons_learned.application.exceptions import ApplicationNotFoundError
from lessons_learned.domain.aggregates.lessons_learned import LessonsLearned
from lessons_learned.domain.aggregates.post_incident_report import PostIncidentReport
from lessons_learned.domain.services.campaign_advisory_service import (
    CampaignRetargetingAdvisoryService,
)
from lessons_learned.domain.services.knowledge_feedback_service import KnowledgeFeedbackService
from lessons_learned.domain.services.lessons_service import LessonsLearnedService
from lessons_learned.domain.services.report_generation_service import (
    PostIncidentReportGenerationService,
)
from lessons_learned.domain.value_objects.enums import (
    ActionItemPriority,
    LessonCategory,
    LessonsRole,
    PostIncidentReportStatus,
    ReportFormat,
)
from lessons_learned.domain.value_objects.identifiers import (
    LessonsLearnedId,
    PostIncidentReportId,
    TenantId,
)


class LessonsApplicationService:
    def __init__(self, ll_repo: Any, report_repo: Any, bus: Any, store: Any, delivery: Any) -> None:
        self._ll = ll_repo
        self._reports = report_repo
        self._bus = bus
        self._store = store
        self._delivery = delivery
        self._gen = PostIncidentReportGenerationService()
        self._advisory = CampaignRetargetingAdvisoryService()
        self._knowledge = KnowledgeFeedbackService()
        self._svc = LessonsLearnedService()
        self.events: list[Any] = []

    async def create_for_incident(
        self,
        tenant_id: UUID,
        incident_id: str,
        roles: tuple[str, ...],
        technique_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        require_at_least(roles, LessonsRole.CONTRIBUTOR)
        tenant = TenantId(tenant_id)
        existing = await self._ll.find_by_incident(tenant, incident_id)
        if existing:
            return {"ll_id": str(existing.ll_id), "status": existing.status.value}
        ll = LessonsLearned.create(
            LessonsLearnedId.generate(), tenant, incident_id, datetime.now(UTC)
        )
        if technique_ids:
            ll.confirmed_technique_ids = list(technique_ids)
        await self._ll.save(tenant, ll)
        self.events.extend(ll.pop_events())
        return {"ll_id": str(ll.ll_id), "status": ll.status.value}

    async def add_lesson(
        self,
        tenant_id: UUID,
        ll_id: UUID,
        category: str,
        description: str,
        impact: str,
        roles: tuple[str, ...],
    ) -> dict[str, Any]:
        require_at_least(roles, LessonsRole.CONTRIBUTOR)
        tenant = TenantId(tenant_id)
        ll = await self._ll.find_by_id(tenant, LessonsLearnedId(ll_id))
        if ll is None:
            raise ApplicationNotFoundError("ll")
        ll.add_lesson(tenant, LessonCategory(category), description, impact)
        await self._ll.save(tenant, ll)
        self.events.extend(ll.pop_events())
        return {"lesson_count": len(ll.lessons)}

    async def add_action(
        self,
        tenant_id: UUID,
        ll_id: UUID,
        title: str,
        description: str,
        owner: str,
        priority: str,
        roles: tuple[str, ...],
    ) -> dict[str, Any]:
        require_at_least(roles, LessonsRole.CONTRIBUTOR)
        tenant = TenantId(tenant_id)
        ll = await self._ll.find_by_id(tenant, LessonsLearnedId(ll_id))
        if ll is None:
            raise ApplicationNotFoundError("ll")
        aid = ll.add_action(tenant, title, description, owner, ActionItemPriority(priority), None)
        await self._ll.save(tenant, ll)
        return {"action_id": aid}

    async def review(
        self, tenant_id: UUID, ll_id: UUID, actor: str, roles: tuple[str, ...]
    ) -> dict[str, Any]:
        require_at_least(roles, LessonsRole.APPROVER)
        tenant = TenantId(tenant_id)
        ll = await self._ll.find_by_id(tenant, LessonsLearnedId(ll_id))
        if ll is None:
            raise ApplicationNotFoundError("ll")
        ll.review(tenant, actor, datetime.now(UTC))
        await self._ll.save(tenant, ll)
        return {"status": ll.status.value}

    async def finalize(
        self, tenant_id: UUID, ll_id: UUID, actor: str, roles: tuple[str, ...]
    ) -> dict[str, Any]:
        require_at_least(roles, LessonsRole.APPROVER)
        tenant = TenantId(tenant_id)
        ll = await self._ll.find_by_id(tenant, LessonsLearnedId(ll_id))
        if ll is None:
            raise ApplicationNotFoundError("ll")
        ll.finalize(tenant, actor, datetime.now(UTC))
        events = ll.pop_events()
        self.events.extend(events)
        for e in self._advisory.extract_events(events):
            await self._bus.publish(e)
        await self._ll.save(tenant, ll)
        return {
            "status": ll.status.value,
            "campaign_suggested": ll.campaign_retargeting_suggestion_ref is not None,
        }

    async def generate_report(
        self, tenant_id: UUID, ll_id: UUID, fmt: str, roles: tuple[str, ...]
    ) -> dict[str, Any]:
        require_at_least(roles, LessonsRole.APPROVER)
        tenant = TenantId(tenant_id)
        ll = await self._ll.find_by_id(tenant, LessonsLearnedId(ll_id))
        if ll is None:
            raise ApplicationNotFoundError("ll")
        report = PostIncidentReport(
            PostIncidentReportId.generate(),
            tenant,
            ll.incident_id,
            ll.ll_id,
            ReportFormat(fmt),
            PostIncidentReportStatus.GENERATING,
        )
        payload = self._gen.generate(
            title=f"Post-Incident Report {ll.incident_id}",
            incident_id=ll.incident_id,
            lessons=[
                {"category": x.category.value, "description": x.description} for x in ll.lessons
            ],
            actions=[{"title": a.title, "status": a.status.value} for a in ll.action_items],
            fmt=ReportFormat(fmt),
        )
        ref = f"pir/{tenant}/{report.report_id}"
        await self._store.store(ref, payload)
        report.complete(tenant, ref, payload, datetime.now(UTC))
        await self._reports.save(tenant, report)
        self.events.extend(report.pop_events())
        return {
            "report_id": str(report.report_id),
            "format": fmt,
            "bytes": len(payload),
            "artifact_ref": ref,
        }

    async def export_report(
        self, tenant_id: UUID, report_id: UUID, destination: str, roles: tuple[str, ...]
    ) -> dict[str, Any]:
        require_at_least(roles, LessonsRole.APPROVER)
        tenant = TenantId(tenant_id)
        report = await self._reports.find_by_id(tenant, PostIncidentReportId(report_id))
        if report is None:
            raise ApplicationNotFoundError("report")
        report.export(tenant, destination, datetime.now(UTC))
        await self._reports.save(tenant, report)
        self.events.extend(report.pop_events())
        if destination.startswith("http"):
            await self._delivery.deliver_webhook(str(tenant), str(report_id), destination)
        else:
            await self._delivery.deliver_email(str(tenant), str(report_id), destination)
        return {"status": report.status.value, "exported_to": destination}

    async def get(self, tenant_id: UUID, incident_id: str) -> dict[str, Any]:
        tenant = TenantId(tenant_id)
        ll = await self._ll.find_by_incident(tenant, incident_id)
        if ll is None:
            raise ApplicationNotFoundError("ll")
        return {
            "ll_id": str(ll.ll_id),
            "status": ll.status.value,
            "incident_id": ll.incident_id,
            "lessons": len(ll.lessons),
            "actions": len(ll.action_items),
            "quality_score": self._svc.quality_score(len(ll.lessons), len(ll.action_items)),
            "techniques": list(ll.confirmed_technique_ids),
        }
