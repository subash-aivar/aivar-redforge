from __future__ import annotations

from pydantic import BaseModel, Field


class RemediationCandidateSchema(BaseModel):
    remediation_id: str
    affected_asset_refs: list[str] = Field(default_factory=list)
    estimated_amplifier_removals: list[str] = Field(default_factory=list)
    estimated_base_reduction: float = 0.0


class GeneratePlanRequest(BaseModel):
    candidate_remediations: list[RemediationCandidateSchema]
    plan_budget: int = Field(default=10, ge=1, le=500)
    top_k: int = Field(default=200, ge=1, le=2000)
    sample_size: int | None = None
    current_exposure_scores: dict[str, float] | None = None
    score_input_version: int = 1


class CommitPlanRequest(BaseModel):
    committed_by: str = Field(min_length=1)
