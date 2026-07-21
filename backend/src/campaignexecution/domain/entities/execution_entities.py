"""campaignexecution domain entities."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from campaignexecution.domain.value_objects.enums import TaskExecutionState, TaskOutcome

if TYPE_CHECKING:
    from datetime import datetime

    from campaignexecution.domain.value_objects.execution_vos import OperationRef
    from campaignexecution.domain.value_objects.identifiers import (
        CampaignTaskId,
        TaskExecutionRecordId,
    )


@dataclass(slots=True)
class TaskExecutionRecord:
    """Runtime execution record for a single task within a TaskGraphExecution."""

    record_id: TaskExecutionRecordId
    task_id: CampaignTaskId
    state: TaskExecutionState
    outcome: TaskOutcome | None
    operation_ref: OperationRef | None
    dispatched_at: datetime | None
    completed_at: datetime | None
    failure_reason: str | None
    is_rollback_task: bool

    def mark_ready(self) -> None:
        self.state = TaskExecutionState.READY_TO_DISPATCH

    def mark_dispatching(self) -> None:
        self.state = TaskExecutionState.DISPATCHING

    def mark_running(self, operation_ref: OperationRef, dispatched_at: datetime) -> None:
        self.state = TaskExecutionState.RUNNING
        self.operation_ref = operation_ref
        self.dispatched_at = dispatched_at

    def mark_completed(self, outcome: TaskOutcome, completed_at: datetime) -> None:
        self.state = TaskExecutionState.COMPLETED
        self.outcome = outcome
        self.completed_at = completed_at

    def mark_failed(self, reason: str, completed_at: datetime) -> None:
        self.state = TaskExecutionState.FAILED
        self.outcome = TaskOutcome.FAILURE
        self.failure_reason = reason
        self.completed_at = completed_at

    def mark_skipped(self) -> None:
        self.state = TaskExecutionState.SKIPPED
        self.outcome = TaskOutcome.SKIPPED

    def mark_timed_out(self, completed_at: datetime) -> None:
        self.state = TaskExecutionState.TIMED_OUT
        self.outcome = TaskOutcome.TIMED_OUT
        self.completed_at = completed_at

    def mark_rolled_back(self, rollback_op: OperationRef, completed_at: datetime) -> None:
        self.state = TaskExecutionState.ROLLED_BACK
        self.operation_ref = rollback_op
        self.completed_at = completed_at

    @property
    def is_terminal(self) -> bool:
        return self.state in {
            TaskExecutionState.COMPLETED,
            TaskExecutionState.FAILED,
            TaskExecutionState.SKIPPED,
            TaskExecutionState.ROLLED_BACK,
            TaskExecutionState.TIMED_OUT,
        }

    @property
    def is_done(self) -> bool:
        """Terminal and eligible for successor evaluation."""
        return self.state in {
            TaskExecutionState.COMPLETED,
            TaskExecutionState.FAILED,
            TaskExecutionState.SKIPPED,
            TaskExecutionState.TIMED_OUT,
        }


@dataclass(slots=True)
class ExecutionTrack:
    """A set of tasks executing in parallel within a campaign."""

    track_id: str
    task_ids: list[CampaignTaskId] = field(default_factory=list)

    def add_task(self, task_id: CampaignTaskId) -> None:
        self.task_ids.append(task_id)


@dataclass(frozen=True, slots=True)
class CheckpointRecord:
    """Immutable state snapshot at an EvaluationCheckpoint task."""

    checkpoint_task_id: CampaignTaskId
    objective_states: tuple[tuple[str, str], ...]
    captured_at: datetime
