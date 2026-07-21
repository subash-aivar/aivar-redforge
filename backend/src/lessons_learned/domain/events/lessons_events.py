from __future__ import annotations

from dataclasses import dataclass

from lessons_learned.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class LessonsLearnedCreated(BaseDomainEvent):
    ll_id: str = ""
    incident_id: str = ""
    created_at: str = ""


@dataclass(frozen=True, slots=True)
class LessonsLearnedCaptured(BaseDomainEvent):
    ll_id: str = ""
    incident_id: str = ""


@dataclass(frozen=True, slots=True)
class LessonsLearnedFinalized(BaseDomainEvent):
    ll_id: str = ""
    incident_id: str = ""
    finalized_by: str = ""
    finalized_at: str = ""


@dataclass(frozen=True, slots=True)
class CampaignRetargetingSuggested(BaseDomainEvent):
    ll_id: str = ""
    incident_id: str = ""
    confirmed_technique_ids: tuple[str, ...] = ()
    attack_vector_description: str = ""
    suggested_scenario_name: str = ""
    suggested_scope: str = ""
    evidence_refs: tuple[str, ...] = ()
    rationale: str = ""
    produced_at: str = ""


@dataclass(frozen=True, slots=True)
class PostIncidentReportGenerated(BaseDomainEvent):
    report_id: str = ""
    ll_id: str = ""
    incident_id: str = ""
    format: str = ""
    generated_at: str = ""


@dataclass(frozen=True, slots=True)
class PostIncidentReportExported(BaseDomainEvent):
    report_id: str = ""
    exported_to: str = ""
    exported_at: str = ""


@dataclass(frozen=True, slots=True)
class KnowledgeFeedbackPublished(BaseDomainEvent):
    ll_id: str = ""
    incident_id: str = ""
    feedback_summary: str = ""
