"""Entities owned by the Operation aggregate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from operation.domain.value_objects.enums import ImpactCeiling, StepState, StepType
    from operation.domain.value_objects.identifiers import (
        ExecutionStepId,
        OperationApprovalId,
        OperationObjectiveId,
        StepDependencyId,
    )
    from operation.domain.value_objects.plan_vos import (
        ExecutionWindowConstraint,
        MitreAttackRef,
        RateLimit,
        StepConstraints,
        StepOutputRef,
        StepTargetRef,
        StepTechniqueRef,
    )


@dataclass(slots=True)
class ExecutionStep:
    step_id: ExecutionStepId
    name: str
    step_type: StepType
    state: StepState
    constraints: StepConstraints
    technique_ref: StepTechniqueRef | None
    target_ref: StepTargetRef | None
    impact_ceiling: ImpactCeiling | None
    modifies_persistent_state: bool
    mitre_ref: MitreAttackRef | None
    rate_limit: RateLimit | None
    window: ExecutionWindowConstraint | None
    output_ref: StepOutputRef | None
    description: str


@dataclass(slots=True)
class StepDependency:
    dependency_id: StepDependencyId
    from_step_id: ExecutionStepId
    to_step_id: ExecutionStepId


@dataclass(slots=True)
class OperationApproval:
    approval_id: OperationApprovalId
    operator_id: UUID
    authority: str
    signature: str
    approved_at: datetime


@dataclass(slots=True)
class OperationObjective:
    objective_id: OperationObjectiveId
    description: str
    success_criteria: str
    is_primary: bool
