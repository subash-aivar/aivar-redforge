from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4

from lessons_learned.domain.events.lessons_events import (
    CampaignRetargetingSuggested,
    KnowledgeFeedbackPublished,
    LessonsLearnedCaptured,
    LessonsLearnedCreated,
    LessonsLearnedFinalized,
)
from lessons_learned.domain.exceptions.domain_exceptions import (
    DomainInvariantViolation,
    InvalidLLTransition,
    TenantMismatch,
)
from lessons_learned.domain.value_objects.enums import (
    ActionItemPriority,
    ActionItemStatus,
    LessonCategory,
    LLStatus,
)
from lessons_learned.domain.value_objects.identifiers import LessonsLearnedId, TenantId


@dataclass
class LessonItem:
    item_id: str
    category: LessonCategory
    description: str
    impact_summary: str


@dataclass
class ImprovementAction:
    action_id: str
    title: str
    description: str
    owner: str
    priority: ActionItemPriority
    due_date: datetime | None
    status: ActionItemStatus
    notes: str = ""


@dataclass
class Recommendation:
    recommendation_id: str
    text: str
    technique_ids: list[str] = field(default_factory=list)


class LessonsLearned:
    def __init__(
        self,
        ll_id: LessonsLearnedId,
        tenant_id: TenantId,
        incident_id: str,
        status: LLStatus,
        created_at: datetime,
    ) -> None:
        self.ll_id = ll_id
        self.tenant_id = tenant_id
        self.incident_id = incident_id
        self.status = status
        self.created_at = created_at
        self.lessons: list[LessonItem] = []
        self.action_items: list[ImprovementAction] = []
        self.recommendations: list[Recommendation] = []
        self.confirmed_technique_ids: list[str] = []
        self.reviewed_by: str | None = None
        self.reviewed_at: datetime | None = None
        self.finalized_by: str | None = None
        self.finalized_at: datetime | None = None
        self.campaign_retargeting_suggestion_ref: str | None = None
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        ev = list(self._pending_events)
        self._pending_events.clear()
        return ev

    @classmethod
    def create(
        cls, ll_id: LessonsLearnedId, tenant_id: TenantId, incident_id: str, at: datetime
    ) -> LessonsLearned:
        ll = cls(ll_id, tenant_id, incident_id, LLStatus.IN_PROGRESS, at)
        ll._pending_events.append(
            LessonsLearnedCreated(
                tenant_id=str(tenant_id),
                aggregate_id=str(ll_id),
                ll_id=str(ll_id),
                incident_id=incident_id,
                created_at=at.isoformat(),
            )
        )
        return ll

    def add_lesson(
        self, tenant_id: TenantId, category: LessonCategory, description: str, impact: str
    ) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        if self.status == LLStatus.FINALIZED:
            raise InvalidLLTransition()
        self.lessons.append(LessonItem(str(uuid4()), category, description, impact))
        self._pending_events.append(
            LessonsLearnedCaptured(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.ll_id),
                ll_id=str(self.ll_id),
                incident_id=self.incident_id,
            )
        )

    def add_action(
        self,
        tenant_id: TenantId,
        title: str,
        description: str,
        owner: str,
        priority: ActionItemPriority,
        due: datetime | None,
    ) -> str:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        aid = str(uuid4())
        self.action_items.append(
            ImprovementAction(aid, title, description, owner, priority, due, ActionItemStatus.OPEN)
        )
        return aid

    def update_action_status(
        self, tenant_id: TenantId, action_id: str, status: ActionItemStatus, notes: str
    ) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        for a in self.action_items:
            if a.action_id == action_id:
                a.status = status
                a.notes = notes
                return
        raise DomainInvariantViolation("action not found")

    def review(self, tenant_id: TenantId, reviewed_by: str, at: datetime) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        if self.status != LLStatus.IN_PROGRESS:
            raise InvalidLLTransition()
        self.status = LLStatus.REVIEWED
        self.reviewed_by = reviewed_by
        self.reviewed_at = at

    def finalize(self, tenant_id: TenantId, finalized_by: str, at: datetime) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        if self.status not in {LLStatus.IN_PROGRESS, LLStatus.REVIEWED}:
            raise InvalidLLTransition()
        self.status = LLStatus.FINALIZED
        self.finalized_by = finalized_by
        self.finalized_at = at
        self._pending_events.append(
            LessonsLearnedFinalized(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.ll_id),
                ll_id=str(self.ll_id),
                incident_id=self.incident_id,
                finalized_by=finalized_by,
                finalized_at=at.isoformat(),
            )
        )
        if self.confirmed_technique_ids:
            self.campaign_retargeting_suggestion_ref = f"crs-{self.ll_id}"
            self._pending_events.append(
                CampaignRetargetingSuggested(
                    tenant_id=str(tenant_id),
                    aggregate_id=str(self.ll_id),
                    ll_id=str(self.ll_id),
                    incident_id=self.incident_id,
                    confirmed_technique_ids=tuple(self.confirmed_technique_ids),
                    attack_vector_description="derived from eradication techniques",
                    suggested_scenario_name="Retarget confirmed techniques",
                    suggested_scope="tenant",
                    evidence_refs=(),
                    rationale="Lessons learned finalized with confirmed techniques",
                    produced_at=at.isoformat(),
                )
            )
        self._pending_events.append(
            KnowledgeFeedbackPublished(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.ll_id),
                ll_id=str(self.ll_id),
                incident_id=self.incident_id,
                feedback_summary=f"{len(self.lessons)} lessons; {len(self.action_items)} actions",
            )
        )
