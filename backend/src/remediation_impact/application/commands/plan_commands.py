"""Commands for ExposureReductionPlan."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from remediation_impact.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class RemediationCandidateInput:
    remediation_id: str
    affected_asset_refs: tuple[str, ...]
    estimated_amplifier_removals: tuple[str, ...] = ()
    estimated_base_reduction: float = 0.0


@dataclass(frozen=True, slots=True)
class GenerateExposureReductionPlanCommand:
    tenant_id: TenantId
    candidate_remediations: tuple[RemediationCandidateInput, ...]
    plan_budget: int = 10
    top_k: int = 200
    sample_size: int | None = None
    current_exposure_scores: dict[str, float] | None = None
    score_input_version: int = 1
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CommitExposureReductionPlanCommand:
    tenant_id: TenantId
    plan_id: UUID
    committed_by: str
    actor_roles: tuple[str, ...] = ()
