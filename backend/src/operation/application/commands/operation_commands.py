"""Commands for operation planning and authorization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from operation.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class CreateOperation:
    tenant_id: TenantId
    engagement_id: UUID
    name: str
    classification: str


@dataclass(frozen=True, slots=True)
class AddExecutionStep:
    tenant_id: TenantId
    operation_id: UUID
    name: str
    step_type: str
    max_duration_seconds: int
    rollback_on_failure: bool = True
    continue_on_failure: bool = False
    technique_payload_id: str | None = None
    technique_id: str | None = None
    target_asset_id: UUID | None = None
    impact_ceiling: str | None = None
    modifies_persistent_state: bool = False
    mitre_technique_id: str | None = None
    mitre_tactic: str | None = None
    rate_limit_max: int | None = None
    rate_limit_window_seconds: int | None = None
    window_allowed_days: tuple[int, ...] | None = None
    window_start_hour: int | None = None
    window_end_hour: int | None = None
    description: str = ""


@dataclass(frozen=True, slots=True)
class RemoveExecutionStep:
    tenant_id: TenantId
    operation_id: UUID
    step_id: UUID


@dataclass(frozen=True, slots=True)
class AddStepDependency:
    tenant_id: TenantId
    operation_id: UUID
    from_step_id: UUID
    to_step_id: UUID


@dataclass(frozen=True, slots=True)
class SetOperationObjectives:
    tenant_id: TenantId
    operation_id: UUID
    objectives: tuple[tuple[str, str, bool], ...]


@dataclass(frozen=True, slots=True)
class ValidateExecutionPlan:
    tenant_id: TenantId
    operation_id: UUID


@dataclass(frozen=True, slots=True)
class SignExecutionPlan:
    tenant_id: TenantId
    operation_id: UUID
    operator_id: UUID
    signature: str


@dataclass(frozen=True, slots=True)
class SubmitOperationForApproval:
    tenant_id: TenantId
    operation_id: UUID


@dataclass(frozen=True, slots=True)
class ApproveOperation:
    tenant_id: TenantId
    operation_id: UUID
    operator_id: UUID
    authority: str
    signature: str


@dataclass(frozen=True, slots=True)
class QueueOperation:
    tenant_id: TenantId
    operation_id: UUID
