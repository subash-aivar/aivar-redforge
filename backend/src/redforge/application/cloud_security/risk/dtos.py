"""DTOs / commands for M26 Phase 7 Cloud Risk Correlation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID


@dataclass(frozen=True, slots=True)
class CalculateRiskCommand:
    organization_id: str
    asset_id: UUID | None = None
    account_id: UUID | None = None
    organization_wide: bool = False
    incremental: bool = False
    asset_ids: tuple[UUID, ...] = ()


@dataclass(frozen=True, slots=True)
class RiskScoreDTO:
    risk_id: str
    organization_id: str
    cloud_asset_id: str
    overall_score: float
    threat_intel_score: float
    compliance_score: float
    identity_score: float
    exposure_score: float
    business_criticality_score: float
    attack_path_score: float
    cspm_score: float
    kubernetes_score: float
    runtime_score: float
    confidence: str
    trend: str
    state: str
    calculation_version: str
    computed_at: datetime
    valid_until: datetime
    score_components: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class RiskSummaryDTO:
    organization_id: str
    total_scores: int
    average_score: float
    critical_count: int
    high_count: int
    by_state: dict[str, int] = field(default_factory=dict)
    by_trend: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RiskFactorDTO:
    factor_id: str
    organization_id: str
    cloud_asset_id: str
    category: str
    source: str
    title: str
    description: str
    score: float
    severity: str
    confidence: str


@dataclass(frozen=True, slots=True)
class RiskAssessmentResultDTO:
    assessment_id: str
    organization_id: str
    scope: str
    target_id: str
    status: str
    assets_evaluated: int
    risks_created: int
    risks_updated: int
    calculation_version: str
    diagnostics: dict[str, Any] = field(default_factory=dict)
