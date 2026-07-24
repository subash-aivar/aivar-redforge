from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from autonomous_intelligence.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class CreateIntelligenceSuggestion:
    tenant_id: TenantId
    target_context: str
    target_id: UUID | None
    target_type: str
    proposed_change_payload: dict[str, object]
    model_id: str
    model_version: int
    confidence_score: float
    supporting_signal_refs: tuple[str, ...]
    rationale_summary: str
    roles: tuple[str, ...]
    created_by: str = "system"


@dataclass(frozen=True, slots=True)
class ApproveSuggestion:
    tenant_id: TenantId
    suggestion_id: UUID
    approved_by: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RejectSuggestion:
    tenant_id: TenantId
    suggestion_id: UUID
    rejected_by: str
    rejection_reason: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MarkSuggestionApplied:
    tenant_id: TenantId
    suggestion_id: UUID
    target_context_ref: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TrainOptimizationModel:
    tenant_id: TenantId
    target_type: str
    model_id: str
    model_version: int
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DeployOptimizationModel:
    tenant_id: TenantId
    model_id: str
    conformity_assessment_ref: str
    accuracy_metrics: dict[str, float]
    roles: tuple[str, ...]
