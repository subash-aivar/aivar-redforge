"""Application commands for campaignexecution context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from campaignexecution.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class InitializeCampaignExecutionCommand:
    tenant_id: TenantId
    campaign_instance_id: UUID
    campaign_id: UUID
    graph_id: UUID
    graph_version: str
    engagement_id: UUID
    task_ids: list[UUID]
    max_concurrent_actions: int = 10
    auto_abort_on_detection: bool = False
    auto_abort_on_objective_failure: bool = False
    blast_radius_ceiling: str = "Medium"


@dataclass(frozen=True, slots=True)
class DispatchTaskSpec:
    task_id: UUID
    technique_id: str
    technique_name: str
    parameters: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class DispatchNextTasksCommand:
    tenant_id: TenantId
    execution_id: UUID
    task_id: UUID | None = None
    technique_id: str = ""
    technique_name: str = ""
    parameters: dict[str, str] = field(default_factory=dict)
    tasks: tuple[DispatchTaskSpec, ...] = ()


@dataclass(frozen=True, slots=True)
class SuccessorPredicateSpec:
    task_id: UUID
    predicate: str
    objective_ref: str | None = None


@dataclass(frozen=True, slots=True)
class RecordTaskCompletionCommand:
    tenant_id: TenantId
    execution_id: UUID
    task_id: UUID
    outcome: str
    ready_successor_ids: list[UUID] = field(default_factory=list)
    skipped_successor_ids: list[UUID] = field(default_factory=list)
    successors: tuple[SuccessorPredicateSpec, ...] = ()


@dataclass(frozen=True, slots=True)
class ResolveConditionalBranchCommand:
    tenant_id: TenantId
    execution_id: UUID
    completed_task_id: UUID
    outcome: str
    successors: tuple[SuccessorPredicateSpec, ...]


@dataclass(frozen=True, slots=True)
class RecordTaskFailureCommand:
    tenant_id: TenantId
    execution_id: UUID
    task_id: UUID
    failure_reason: str


@dataclass(frozen=True, slots=True)
class EvaluateBarrierCommand:
    tenant_id: TenantId
    execution_id: UUID
    barrier_task_id: UUID
    task_group_task_ids: list[UUID]


@dataclass(frozen=True, slots=True)
class ReachHumanApprovalGateCommand:
    tenant_id: TenantId
    execution_id: UUID
    task_id: UUID
    gate_timeout_seconds: int
    required_approver_role: str
    default_on_timeout: str = "abort"


@dataclass(frozen=True, slots=True)
class GrantHumanApprovalCommand:
    tenant_id: TenantId
    execution_id: UUID
    approver_id: str


@dataclass(frozen=True, slots=True)
class DenyHumanApprovalCommand:
    tenant_id: TenantId
    execution_id: UUID
    approver_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class HandleApprovalTimeoutCommand:
    tenant_id: TenantId
    execution_id: UUID


@dataclass(frozen=True, slots=True)
class PauseCampaignExecutionCommand:
    tenant_id: TenantId
    execution_id: UUID
    reason: str


@dataclass(frozen=True, slots=True)
class ResumeCampaignExecutionCommand:
    tenant_id: TenantId
    execution_id: UUID


@dataclass(frozen=True, slots=True)
class HandleKillSwitchTriggeredCommand:
    tenant_id: TenantId
    execution_id: UUID


@dataclass(frozen=True, slots=True)
class RollbackStepSpec:
    task_id: UUID
    technique_id: str
    technique_name: str
    parameters: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class InitiateRollbackCommand:
    tenant_id: TenantId
    execution_id: UUID
    trigger_reason: str
    rollback_eligible_task_ids: list[UUID] = field(default_factory=list)
    steps: tuple[RollbackStepSpec, ...] = ()


@dataclass(frozen=True, slots=True)
class CompleteExecutionCommand:
    tenant_id: TenantId
    execution_id: UUID


@dataclass(frozen=True, slots=True)
class AbortExecutionCommand:
    tenant_id: TenantId
    execution_id: UUID
    abort_reason: str


@dataclass(frozen=True, slots=True)
class TriggerAutoAbortOnDetectionCommand:
    tenant_id: TenantId
    campaign_instance_id: UUID
    detection_detail: str


@dataclass(frozen=True, slots=True)
class GetExecutionQuery:
    tenant_id: TenantId
    execution_id: UUID
