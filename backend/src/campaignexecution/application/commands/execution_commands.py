"""Application commands for campaignexecution context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class InitializeCampaignExecutionCommand:
    tenant_id: UUID
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
class DispatchNextTasksCommand:
    tenant_id: UUID
    execution_id: UUID
    task_id: UUID
    technique_id: str
    technique_name: str
    parameters: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RecordTaskCompletionCommand:
    tenant_id: UUID
    execution_id: UUID
    task_id: UUID
    outcome: str
    # Optional successor resolution results
    ready_successor_ids: list[UUID] = field(default_factory=list)
    skipped_successor_ids: list[UUID] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class RecordTaskFailureCommand:
    tenant_id: UUID
    execution_id: UUID
    task_id: UUID
    failure_reason: str


@dataclass(frozen=True, slots=True)
class EvaluateBarrierCommand:
    tenant_id: UUID
    execution_id: UUID
    barrier_task_id: UUID
    task_group_task_ids: list[UUID]


@dataclass(frozen=True, slots=True)
class GrantHumanApprovalCommand:
    tenant_id: UUID
    execution_id: UUID
    approver_id: str


@dataclass(frozen=True, slots=True)
class DenyHumanApprovalCommand:
    tenant_id: UUID
    execution_id: UUID
    approver_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class PauseCampaignExecutionCommand:
    tenant_id: UUID
    execution_id: UUID
    reason: str


@dataclass(frozen=True, slots=True)
class ResumeCampaignExecutionCommand:
    tenant_id: UUID
    execution_id: UUID


@dataclass(frozen=True, slots=True)
class InitiateRollbackCommand:
    tenant_id: UUID
    execution_id: UUID
    trigger_reason: str
    rollback_eligible_task_ids: list[UUID] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class CompleteExecutionCommand:
    tenant_id: UUID
    execution_id: UUID


@dataclass(frozen=True, slots=True)
class AbortExecutionCommand:
    tenant_id: UUID
    execution_id: UUID
    abort_reason: str


@dataclass(frozen=True, slots=True)
class TriggerAutoAbortOnDetectionCommand:
    tenant_id: UUID
    campaign_instance_id: UUID
    detection_detail: str


@dataclass(frozen=True, slots=True)
class GetExecutionQuery:
    tenant_id: UUID
    execution_id: UUID
