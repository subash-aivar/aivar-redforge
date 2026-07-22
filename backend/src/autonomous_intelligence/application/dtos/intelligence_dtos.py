from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SuggestionDTO:
    suggestion_id: str
    tenant_id: str
    target_type: str
    status: str
    confidence_score: float
    rationale_summary: str
    model_id: str
    model_version: int
    review_deadline_at: str


@dataclass(frozen=True, slots=True)
class ModelDTO:
    model_id: str
    tenant_id: str
    target_type: str
    model_version: int
    status: str
    accuracy_metrics: dict[str, float]
    feedback_sample_count: int


@dataclass(frozen=True, slots=True)
class PolicyDTO:
    tenant_id: str
    kill_switch_active: bool
    review_required: bool
    enabled_target_types: list[str]
