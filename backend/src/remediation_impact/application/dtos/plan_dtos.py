"""DTOs for remediation_impact."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class PlanStepDTO:
    remediation_id: str
    marginal_delta: float
    affected_asset_refs: list[str]
    rank: int


@dataclass(slots=True)
class ExposureReductionPlanDTO:
    plan_id: str
    tenant_id: str
    status: str
    generated_at: str
    committed_at: str | None
    committed_by: str | None
    is_stale: bool
    projected_exposure_reduction: float
    estimated_business_impact: float
    algorithm: str
    top_k: int
    sample_size: int
    approximation_mode: str
    simulation_seed: int
    score_input_version: int
    plan_steps: list[PlanStepDTO]
    metadata: dict[str, Any]
