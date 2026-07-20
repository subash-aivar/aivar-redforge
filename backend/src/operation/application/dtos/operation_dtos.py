"""DTOs for operation application services."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ExecutionStepDTO:
    id: str
    name: str
    step_type: str
    state: str
    impact_ceiling: str | None
    modifies_persistent_state: bool
    technique_id: str | None
    target_asset_id: str | None


@dataclass(frozen=True, slots=True)
class StepDependencyDTO:
    id: str
    from_step_id: str
    to_step_id: str


@dataclass(frozen=True, slots=True)
class OperationApprovalDTO:
    id: str
    operator_id: str
    authority: str
    approved_at: str


@dataclass(frozen=True, slots=True)
class OperationObjectiveDTO:
    id: str
    description: str
    success_criteria: str
    is_primary: bool


@dataclass(frozen=True, slots=True)
class OperationDTO:
    id: str
    tenant_id: str
    engagement_id: str
    name: str
    classification: str
    state: str
    risk: str
    steps: tuple[ExecutionStepDTO, ...]
    dependencies: tuple[StepDependencyDTO, ...]
    approvals: tuple[OperationApprovalDTO, ...]
    objectives: tuple[OperationObjectiveDTO, ...]
    abort_reason: str | None
    created_at: str
    updated_at: str
    version: int


@dataclass(frozen=True, slots=True)
class PlanValidationResultDTO:
    operation_id: str
    valid: bool
    message: str


@dataclass(frozen=True, slots=True)
class ExecutionPlanVersionDTO:
    id: str
    tenant_id: str
    operation_id: str
    version_number: int
    state: str
    plan_hash: str | None
    signed_by_operator_id: str | None
    signed_at: str | None
    created_at: str
    updated_at: str
    version: int
