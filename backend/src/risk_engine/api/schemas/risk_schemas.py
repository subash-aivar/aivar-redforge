"""Pydantic request/response schemas for risk_engine's API boundary
(M48F). Deliberately separate from the application-layer DTOs in
`risk_engine.application.dtos` — mirrors `operation.api.schemas.
operation_schemas`' convention of a plain-`BaseModel`,
`model_validate(asdict(dto))`-friendly response shape."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class RiskSignalReferenceRequest(BaseModel):
    source_context: str = Field(min_length=1, max_length=128)
    source_aggregate_type: str = Field(min_length=1, max_length=128)
    source_id: str = Field(min_length=1, max_length=256)
    signal_type: str
    raw_value: float
    raw_scale: str
    observed_at: datetime
    subject_reference: str | None = None


class CreateRiskProfileRequest(BaseModel):
    subject_reference: str = Field(min_length=1, max_length=512)
    dimension: str
    signal_reference: RiskSignalReferenceRequest
    profile_id: str | None = None


class RiskDimensionSignalRequest(BaseModel):
    dimension: str
    signal_reference: RiskSignalReferenceRequest


class RiskWeightProfileRequest(BaseModel):
    profile_name: str = Field(min_length=1, max_length=128)
    version: int = Field(ge=1)
    weights: dict[str, float]


class RecomputeRiskProfileRequest(BaseModel):
    signals: list[RiskDimensionSignalRequest] = Field(min_length=1)
    weight_profile: RiskWeightProfileRequest


class AcceptRiskProfileRequest(BaseModel):
    expires_at: datetime


class RiskContributionResponse(BaseModel):
    dimension: str
    normalized_score: float
    source_context: str
    source_id: str
    computed_at: datetime
    subject_reference: str | None = None


class RiskProfileResponse(BaseModel):
    profile_id: str
    tenant_id: str
    subject_reference: str
    status: str
    created_at: datetime
    updated_at: datetime
    composite_score: float | None = None
    weight_profile_id: str | None = None
    composite_computed_at: datetime | None = None
    accepted_expires_at: datetime | None = None
    contributions: list[RiskContributionResponse] = Field(default_factory=list)


class ListRiskProfilesResponse(BaseModel):
    items: list[RiskProfileResponse]
    count: int


class RiskCorrelationResponse(BaseModel):
    correlation_set_id: str
    tenant_id: str
    formed_at: datetime
    signal_references: list[str] = Field(default_factory=list)


class ListRiskCorrelationsResponse(BaseModel):
    items: list[RiskCorrelationResponse]
    count: int


class FormRiskCorrelationSetsRequest(BaseModel):
    signal_references: list[RiskSignalReferenceRequest] = Field(min_length=1)
    correlation_window_seconds: int = Field(gt=0)


class RiskCorrelationFormationResponse(BaseModel):
    tenant_id: str
    correlation_sets: list[RiskCorrelationResponse] = Field(default_factory=list)
    uncorrelated_signal_count: int = 0


class RiskScoreSnapshotResponse(BaseModel):
    value: float
    weight_profile_id: str
    computed_at: datetime


class RiskTimelineResponse(BaseModel):
    profile_id: str
    tenant_id: str
    snapshots: list[RiskScoreSnapshotResponse] = Field(default_factory=list)
    trend_direction: str


class EvaluateEscalationRequest(BaseModel):
    critical_threshold: float = Field(ge=0.0, le=10.0)


class RiskEscalationDecisionResponse(BaseModel):
    profile_id: str
    tenant_id: str
    should_escalate: bool
    composite_score: float | None
    critical_threshold: float


class EvaluateAcceptanceExpiryRequest(BaseModel):
    critical_threshold: float = Field(ge=0.0, le=10.0)


class RiskAcceptanceExpiryDecisionResponse(BaseModel):
    profile_id: str
    tenant_id: str
    expired: bool
    escalation_overrides: bool
    closed: bool
