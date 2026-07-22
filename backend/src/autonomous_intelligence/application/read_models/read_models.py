from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class SuggestionQueueReadModel:
    suggestion_id: str
    target_type: str
    confidence_score: float
    rationale_summary: str
    target_context: str
    target_id: str | None
    model_id: str
    model_version: int
    created_at: datetime
    review_deadline_at: datetime


@dataclass(frozen=True)
class AcceptanceRateReadModel:
    target_type: str
    total_suggestions: int
    approved: int
    rejected: int
    expired: int
    acceptance_rate_pct: float
    trailing_30d_trend: float


@dataclass(frozen=True)
class ModelAccuracyReadModel:
    model_id: str
    target_type: str
    model_version: int
    status: str
    deployed_at: datetime | None
    precision: float | None
    recall: float | None
    rank_correlation: float | None
    feedback_sample_count: int
    accuracy_trend: float


@dataclass(frozen=True)
class PolicyReadModel:
    tenant_id: str
    kill_switch_active: bool
    review_required: bool
    enabled_target_types: list[str]
    min_confidence_by_type: dict[str, float]


@dataclass(frozen=True)
class PostureForecastReadModel:
    forecast_id: str
    tenant_id: str
    predicted_30d: float
    predicted_60d: float
    predicted_90d: float
    baseline_exposure_score: float
    generated_at: datetime


@dataclass(frozen=True)
class ThreatHuntQueueReadModel:
    candidate_id: str
    tenant_id: str
    confidence_score: float
    candidate_status: str
    technique_coverage: tuple[str, ...]
    generated_at: datetime
