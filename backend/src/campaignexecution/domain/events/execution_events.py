"""campaignexecution domain events — all TaskGraphExecution lifecycle events."""

from __future__ import annotations

from dataclasses import dataclass

from campaignexecution.domain.events.base import BaseDomainEvent

# ── TaskGraphExecution events ─────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class TaskGraphExecutionInitialized(BaseDomainEvent):
    campaign_instance_id: str
    graph_id: str
    graph_version: str
    task_count: int


@dataclass(frozen=True, slots=True)
class ExecutionTrackStarted(BaseDomainEvent):
    track_id: str
    task_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TaskDispatched(BaseDomainEvent):
    task_id: str
    operation_id: str
    campaign_instance_id: str


@dataclass(frozen=True, slots=True)
class TaskCompleted(BaseDomainEvent):
    task_id: str
    outcome: str
    operation_id: str


@dataclass(frozen=True, slots=True)
class TaskFailed(BaseDomainEvent):
    task_id: str
    failure_reason: str
    operation_id: str


@dataclass(frozen=True, slots=True)
class TaskTimedOut(BaseDomainEvent):
    task_id: str
    timeout_seconds: int


@dataclass(frozen=True, slots=True)
class TaskSkipped(BaseDomainEvent):
    task_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class BarrierPassed(BaseDomainEvent):
    barrier_task_id: str
    task_group_id: str
    completed_task_count: int


@dataclass(frozen=True, slots=True)
class HumanApprovalGateReached(BaseDomainEvent):
    task_id: str
    gate_timeout_seconds: int
    required_approver_role: str
    default_on_timeout: str


@dataclass(frozen=True, slots=True)
class HumanApprovalGranted(BaseDomainEvent):
    task_id: str
    approver_id: str


@dataclass(frozen=True, slots=True)
class HumanApprovalDenied(BaseDomainEvent):
    task_id: str
    approver_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class ApprovalGateTimedOutProceeded(BaseDomainEvent):
    """Audit record when approval gate timed out and default_on_timeout='proceed'."""

    task_id: str
    gate_timeout_seconds: int


@dataclass(frozen=True, slots=True)
class ConditionalBranchResolved(BaseDomainEvent):
    completed_task_id: str
    outcome: str
    ready_task_ids: tuple[str, ...]
    skipped_task_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EvaluationCheckpointReached(BaseDomainEvent):
    checkpoint_task_id: str
    objective_states: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class RollbackInitiated(BaseDomainEvent):
    trigger_reason: str
    task_count_to_rollback: int


@dataclass(frozen=True, slots=True)
class TaskRolledBack(BaseDomainEvent):
    task_id: str
    rollback_operation_id: str


@dataclass(frozen=True, slots=True)
class RollbackCompleted(BaseDomainEvent):
    rolled_back_count: int


@dataclass(frozen=True, slots=True)
class ExecutionCompleted(BaseDomainEvent):
    campaign_instance_id: str
    tasks_completed: int
    tasks_skipped: int
    tasks_failed: int


@dataclass(frozen=True, slots=True)
class ExecutionFailed(BaseDomainEvent):
    campaign_instance_id: str
    failure_reason: str


@dataclass(frozen=True, slots=True)
class ExecutionAborted(BaseDomainEvent):
    campaign_instance_id: str
    abort_reason: str


@dataclass(frozen=True, slots=True)
class SafetyPolicyBreached(BaseDomainEvent):
    breach_type: str
    details: str
    auto_abort_triggered: bool


# ── CampaignSafetyMonitor events ──────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class SafetyMonitorInitialized(BaseDomainEvent):
    campaign_instance_id: str
    max_concurrent_actions: int
    auto_abort_on_detection: bool


@dataclass(frozen=True, slots=True)
class ConcurrentActionRegistered(BaseDomainEvent):
    operation_id: str
    current_count: int
    ceiling: int


@dataclass(frozen=True, slots=True)
class ConcurrentActionReleased(BaseDomainEvent):
    operation_id: str
    current_count: int


@dataclass(frozen=True, slots=True)
class SafetyMonitorAborted(BaseDomainEvent):
    campaign_instance_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class SafetyMonitorReleased(BaseDomainEvent):
    campaign_instance_id: str
