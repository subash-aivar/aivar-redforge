from __future__ import annotations

from dataclasses import dataclass

from autonomous_intelligence.domain.events.base import BaseIntelligenceEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionCreated(BaseIntelligenceEvent):
    suggestion_id: str
    target_type: str
    confidence_score: float
    model_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionApproved(BaseIntelligenceEvent):
    suggestion_id: str
    approved_by: str
    target_type: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionRejected(BaseIntelligenceEvent):
    suggestion_id: str
    rejected_by: str
    rejection_reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionProposedForApplication(BaseIntelligenceEvent):
    suggestion_id: str
    target_type: str
    target_context: str
    target_id: str | None
    proposal_payload: dict[str, object]


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionApplied(BaseIntelligenceEvent):
    suggestion_id: str
    applied_at: str
    target_context_ref: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionExpired(BaseIntelligenceEvent):
    suggestion_id: str
    expired_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionWithdrawn(BaseIntelligenceEvent):
    suggestion_id: str
    withdrawn_at: str
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionOutcomeCaptured(BaseIntelligenceEvent):
    suggestion_id: str
    delta: float | None
    horizon_days: int
    target_type: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ModelDeployed(BaseIntelligenceEvent):
    model_id: str
    target_type: str
    model_version: int
    accuracy_metrics: dict[str, float]


@dataclass(frozen=True, slots=True, kw_only=True)
class ModelDeprecated(BaseIntelligenceEvent):
    model_id: str
    superseded_by_version: int
