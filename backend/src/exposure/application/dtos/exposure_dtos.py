from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class RiskAmplifierDTO:
    amplifier_id: str
    type: str
    source_ref: str
    applied_weight: float
    is_active: bool
    first_observed_at: str
    last_confirmed_at: str


@dataclass(frozen=True, slots=True)
class ExposureRecordDTO:
    record_id: str
    tenant_id: str
    asset_ref_id: str
    signal_domain: str
    signal_source_ref: str
    status: str
    base_exposure_level: float
    current_exposure_score: float
    version: int
    amplifiers: list[RiskAmplifierDTO] = field(default_factory=list)
    suppression_justification: str | None = None


@dataclass(frozen=True, slots=True)
class ExposureScoreDTO:
    asset_ref_id: str
    composite_score: float
    score_input_version: int
    computed_at: str
    job_id: str
    pending_update: bool = False


@dataclass(frozen=True, slots=True)
class AmplifierWeightConfigurationDTO:
    tenant_id: str
    version: int
    weights: dict[str, float]
    change_rationale: str
    changed_by: str
    created_at: str


@dataclass(frozen=True, slots=True)
class TenantExposureProfileDTO:
    tenant_id: str
    asset_scores: dict[str, float]
    tenant_exposure_score: float
    recomputing: bool
    recomputation_failed_at: str | None
    metadata: dict[str, Any] = field(default_factory=dict)
