"""TaskGraphExecution aggregate root — runtime execution state of a campaign."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from campaignexecution.domain.entities.execution_entities import (
    CheckpointRecord,
    ExecutionTrack,
    TaskExecutionRecord,
)
from campaignexecution.domain.events.execution_events import (
    ApprovalGateTimedOutProceeded,
    BarrierPassed,
    ConditionalBranchResolved,
    ExecutionAborted,
    ExecutionCompleted,
    ExecutionFailed,
    HumanApprovalDenied,
    HumanApprovalGateReached,
    HumanApprovalGranted,
    RollbackCompleted,
    RollbackInitiated,
    SafetyPolicyBreached,
    TaskDispatched,
    TaskFailed,
    TaskGraphExecutionInitialized,
    TaskRolledBack,
    TaskSkipped,
    TaskTimedOut,
)
from campaignexecution.domain.events.execution_events import (
    TaskCompleted as TaskCompletedEvent,
)
from campaignexecution.domain.exceptions.domain_exceptions import (
    BarrierNotPassable,
    InvalidStateTransition,
    NoApprovalGatePending,
    RollbackNotAllowed,
    TaskAlreadyDispatched,
    TaskNotFound,
    TaskNotReadyToDispatch,
    TenantMismatch,
)
from campaignexecution.domain.value_objects.enums import (
    ExecutionState,
    TaskExecutionState,
    TaskOutcome,
)
from campaignexecution.domain.value_objects.identifiers import (
    CampaignTaskId,
    TaskExecutionRecordId,
    TaskGraphExecutionId,
)

if TYPE_CHECKING:
    from datetime import datetime

    from campaignexecution.domain.events.base import BaseDomainEvent
    from campaignexecution.domain.value_objects.execution_vos import (
        CampaignInstanceRef,
        EngagementRef,
        ObjectiveStateMap,
        OperationRef,
        PendingApprovalGate,
        PolicySnapshot,
        TaskGraphVersionRef,
    )
    from campaignexecution.domain.value_objects.identifiers import TenantId

_ALLOWED_TRANSITIONS: dict[ExecutionState, frozenset[ExecutionState]] = {
    ExecutionState.INITIALIZING: frozenset({ExecutionState.RUNNING, ExecutionState.FAILED}),
    ExecutionState.RUNNING: frozenset({
        ExecutionState.WAITING_FOR_APPROVAL,
        ExecutionState.PAUSED,
        ExecutionState.COMPLETED,
        ExecutionState.FAILED,
        ExecutionState.ABORTED,
    }),
    ExecutionState.WAITING_FOR_APPROVAL: frozenset({
        ExecutionState.RUNNING,
        ExecutionState.PAUSED,
        ExecutionState.FAILED,
        ExecutionState.ABORTED,
    }),
    ExecutionState.PAUSED: frozenset({
        ExecutionState.RUNNING,
        ExecutionState.ROLLING_BACK,
        ExecutionState.ABORTED,
    }),
    ExecutionState.ROLLING_BACK: frozenset({ExecutionState.FAILED, ExecutionState.ABORTED}),
    ExecutionState.COMPLETED: frozenset(),
    ExecutionState.FAILED: frozenset(),
    ExecutionState.ABORTED: frozenset(),
}


class TaskGraphExecution:
    """Runtime execution state for one campaign instance run.

    Tracks which tasks have been dispatched to M29, which have completed,
    the active branch path, pending approval gates, safety policy snapshot,
    and rollback state. Uses optimistic locking via _version.
    """

    __slots__ = (
        "_pending_events",
        "_version",
        "campaign_instance_ref",
        "checkpoints",
        "engagement_ref",
        "execution_id",
        "graph_version_ref",
        "objective_states",
        "pending_approval_gate",
        "policy_snapshot",
        "state",
        "task_records",
        "tenant_id",
        "tracks",
    )

    def __init__(
        self,
        execution_id: TaskGraphExecutionId,
        tenant_id: TenantId,
        campaign_instance_ref: CampaignInstanceRef,
        graph_version_ref: TaskGraphVersionRef,
        engagement_ref: EngagementRef,
        policy_snapshot: PolicySnapshot,
        state: ExecutionState,
        task_records: list[TaskExecutionRecord],
        tracks: list[ExecutionTrack],
        checkpoints: list[CheckpointRecord],
        objective_states: ObjectiveStateMap,
        pending_approval_gate: PendingApprovalGate | None,
        version: int,
    ) -> None:
        self.execution_id = execution_id
        self.tenant_id = tenant_id
        self.campaign_instance_ref = campaign_instance_ref
        self.graph_version_ref = graph_version_ref
        self.engagement_ref = engagement_ref
        self.policy_snapshot = policy_snapshot
        self.state = state
        self.task_records = list(task_records)
        self.tracks = list(tracks)
        self.checkpoints = list(checkpoints)
        self.objective_states = objective_states
        self.pending_approval_gate = pending_approval_gate
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    # ── Identity / properties ────────────────────────────────────────────────

    @property
    def version(self) -> int:
        return self._version

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _mutate(self) -> None:
        self._version += 1

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _transition(self, to_state: ExecutionState) -> None:
        allowed = _ALLOWED_TRANSITIONS.get(self.state, frozenset())
        if to_state not in allowed:
            raise InvalidStateTransition(
                self.state.value, f"→{to_state.value}", str(self.execution_id)
            )
        self.state = to_state

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def initialize(
        cls,
        execution_id: TaskGraphExecutionId,
        tenant_id: TenantId,
        campaign_instance_ref: CampaignInstanceRef,
        graph_version_ref: TaskGraphVersionRef,
        engagement_ref: EngagementRef,
        policy_snapshot: PolicySnapshot,
        task_ids: list[CampaignTaskId],
        now: datetime,
    ) -> TaskGraphExecution:
        from campaignexecution.domain.value_objects.execution_vos import ObjectiveStateMap

        task_records = [
            TaskExecutionRecord(
                record_id=TaskExecutionRecordId.generate(),
                task_id=tid,
                state=TaskExecutionState.PENDING,
                outcome=None,
                operation_ref=None,
                dispatched_at=None,
                completed_at=None,
                failure_reason=None,
                is_rollback_task=False,
            )
            for tid in task_ids
        ]

        execution = cls(
            execution_id=execution_id,
            tenant_id=tenant_id,
            campaign_instance_ref=campaign_instance_ref,
            graph_version_ref=graph_version_ref,
            engagement_ref=engagement_ref,
            policy_snapshot=policy_snapshot,
            state=ExecutionState.INITIALIZING,
            task_records=task_records,
            tracks=[],
            checkpoints=[],
            objective_states=ObjectiveStateMap(),
            pending_approval_gate=None,
            version=1,
        )
        execution._emit(
            TaskGraphExecutionInitialized(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(execution_id),
                aggregate_type="TaskGraphExecution",
                campaign_instance_id=str(campaign_instance_ref.instance_id),
                graph_id=str(graph_version_ref.graph_id),
                graph_version=graph_version_ref.version_str,
                task_count=len(task_ids),
            )
        )
        return execution

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _find_record(self, task_id: CampaignTaskId) -> TaskExecutionRecord:
        for rec in self.task_records:
            if rec.task_id == task_id:
                return rec
        raise TaskNotFound(str(task_id))

    def get_ready_task_ids(self) -> list[CampaignTaskId]:
        return [
            r.task_id for r in self.task_records
            if r.state == TaskExecutionState.READY_TO_DISPATCH
        ]

    def get_running_task_ids(self) -> list[CampaignTaskId]:
        return [r.task_id for r in self.task_records if r.state == TaskExecutionState.RUNNING]

    def concurrent_action_count(self) -> int:
        return len([r for r in self.task_records if r.state == TaskExecutionState.RUNNING])

    # ── Lifecycle methods ─────────────────────────────────────────────────────

    def mark_running(self, now: datetime) -> None:
        self._transition(ExecutionState.RUNNING)
        self._mutate()

    def mark_task_ready(
        self, tenant_id: TenantId, task_id: CampaignTaskId, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        rec = self._find_record(task_id)
        if rec.state not in {TaskExecutionState.PENDING}:
            raise TaskNotReadyToDispatch(str(task_id), rec.state.value)
        rec.mark_ready()
        self._mutate()

    def record_task_dispatched(
        self,
        tenant_id: TenantId,
        task_id: CampaignTaskId,
        operation_ref: OperationRef,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        rec = self._find_record(task_id)
        if rec.state == TaskExecutionState.RUNNING:
            # Idempotent: already dispatched → return existing ref
            return
        if rec.state not in {TaskExecutionState.READY_TO_DISPATCH, TaskExecutionState.DISPATCHING}:
            raise TaskAlreadyDispatched(str(task_id))
        rec.mark_running(operation_ref, now)
        self._mutate()
        self._emit(
            TaskDispatched(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(self.execution_id),
                aggregate_type="TaskGraphExecution",
                task_id=str(task_id),
                operation_id=str(operation_ref.operation_id),
                campaign_instance_id=str(self.campaign_instance_ref.instance_id),
            )
        )

    def record_task_completion(
        self,
        tenant_id: TenantId,
        task_id: CampaignTaskId,
        outcome: TaskOutcome,
        now: datetime,
        ready_successor_ids: list[CampaignTaskId] | None = None,
        skipped_successor_ids: list[CampaignTaskId] | None = None,
    ) -> None:
        self._assert_tenant(tenant_id)
        rec = self._find_record(task_id)

        # Idempotency: already completed → no-op
        if rec.is_terminal:
            return

        rec.mark_completed(outcome, now)
        self._mutate()

        op_id = str(rec.operation_ref.operation_id) if rec.operation_ref else ""
        self._emit(
            TaskCompletedEvent(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(self.execution_id),
                aggregate_type="TaskGraphExecution",
                task_id=str(task_id),
                outcome=outcome.value,
                operation_id=op_id,
            )
        )

        # Mark successors ready / skipped
        if ready_successor_ids:
            for sid in ready_successor_ids:
                try:
                    succ = self._find_record(sid)
                    if succ.state == TaskExecutionState.PENDING:
                        succ.mark_ready()
                except TaskNotFound:
                    pass

        if skipped_successor_ids:
            for sid in skipped_successor_ids:
                try:
                    succ = self._find_record(sid)
                    ready_states = {
                            TaskExecutionState.PENDING, TaskExecutionState.READY_TO_DISPATCH
                        }
                    if succ.state in ready_states:
                        succ.mark_skipped()
                        self._emit(
                            TaskSkipped(
                                event_id=str(uuid7()),
                                occurred_at=now,
                                tenant_id=str(tenant_id),
                                aggregate_id=str(self.execution_id),
                                aggregate_type="TaskGraphExecution",
                                task_id=str(sid),
                                reason=f"Conditional branch not taken after task {task_id}",
                            )
                        )
                except TaskNotFound:
                    pass

        if ready_successor_ids or skipped_successor_ids:
            self._emit(
                ConditionalBranchResolved(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=str(tenant_id),
                    aggregate_id=str(self.execution_id),
                    aggregate_type="TaskGraphExecution",
                    completed_task_id=str(task_id),
                    outcome=outcome.value,
                    ready_task_ids=tuple(str(tid) for tid in (ready_successor_ids or [])),
                    skipped_task_ids=tuple(str(tid) for tid in (skipped_successor_ids or [])),
                )
            )

    def record_task_failure(
        self,
        tenant_id: TenantId,
        task_id: CampaignTaskId,
        failure_reason: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        rec = self._find_record(task_id)
        if rec.is_terminal:
            return
        rec.mark_failed(failure_reason, now)
        self._mutate()
        op_id = str(rec.operation_ref.operation_id) if rec.operation_ref else ""
        self._emit(
            TaskFailed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(self.execution_id),
                aggregate_type="TaskGraphExecution",
                task_id=str(task_id),
                failure_reason=failure_reason,
                operation_id=op_id,
            )
        )

    def record_task_timeout(
        self,
        tenant_id: TenantId,
        task_id: CampaignTaskId,
        timeout_seconds: int,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        rec = self._find_record(task_id)
        if rec.is_terminal:
            return
        rec.mark_timed_out(now)
        self._mutate()
        self._emit(
            TaskTimedOut(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(self.execution_id),
                aggregate_type="TaskGraphExecution",
                task_id=str(task_id),
                timeout_seconds=timeout_seconds,
            )
        )

    def evaluate_barrier(
        self,
        tenant_id: TenantId,
        barrier_task_id: CampaignTaskId,
        task_group_task_ids: list[CampaignTaskId],
        now: datetime,
    ) -> None:
        """Check if all tasks in the barrier's group are done; if so, mark barrier ready."""
        self._assert_tenant(tenant_id)
        pending = []
        for tid in task_group_task_ids:
            try:
                rec = self._find_record(tid)
                if not rec.is_done:
                    pending.append(tid)
            except TaskNotFound:
                pass

        if pending:
            raise BarrierNotPassable(str(barrier_task_id), len(pending))

        barrier_rec = self._find_record(barrier_task_id)
        if barrier_rec.state == TaskExecutionState.PENDING:
            barrier_rec.mark_ready()
            self._mutate()
            self._emit(
                BarrierPassed(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=str(tenant_id),
                    aggregate_id=str(self.execution_id),
                    aggregate_type="TaskGraphExecution",
                    barrier_task_id=str(barrier_task_id),
                    task_group_id=str(task_group_task_ids[0]) if task_group_task_ids else "",
                    completed_task_count=len(task_group_task_ids),
                )
            )

    def reach_human_approval_gate(
        self,
        tenant_id: TenantId,
        pending_gate: PendingApprovalGate,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self.pending_approval_gate = pending_gate
        self._transition(ExecutionState.WAITING_FOR_APPROVAL)
        self._mutate()
        self._emit(
            HumanApprovalGateReached(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(self.execution_id),
                aggregate_type="TaskGraphExecution",
                task_id=str(pending_gate.task_id),
                gate_timeout_seconds=pending_gate.gate_timeout_seconds,
                required_approver_role=pending_gate.required_approver_role,
                default_on_timeout=pending_gate.default_on_timeout,
            )
        )

    def grant_human_approval(
        self,
        tenant_id: TenantId,
        approver_id: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.pending_approval_gate is None:
            raise NoApprovalGatePending(str(self.execution_id))
        gate = self.pending_approval_gate
        self.pending_approval_gate = None

        # Mark approval task as completed so successors can proceed
        rec = self._find_record(gate.task_id)
        rec.mark_completed(TaskOutcome.SUCCESS, now)

        self._transition(ExecutionState.RUNNING)
        self._mutate()
        self._emit(
            HumanApprovalGranted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(self.execution_id),
                aggregate_type="TaskGraphExecution",
                task_id=str(gate.task_id),
                approver_id=approver_id,
            )
        )

    def deny_human_approval(
        self,
        tenant_id: TenantId,
        approver_id: str,
        reason: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.pending_approval_gate is None:
            raise NoApprovalGatePending(str(self.execution_id))
        gate = self.pending_approval_gate
        self.pending_approval_gate = None

        rec = self._find_record(gate.task_id)
        rec.mark_failed(f"Approval denied by {approver_id}: {reason}", now)

        self._transition(ExecutionState.PAUSED)
        self._mutate()
        self._emit(
            HumanApprovalDenied(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(self.execution_id),
                aggregate_type="TaskGraphExecution",
                task_id=str(gate.task_id),
                approver_id=approver_id,
                reason=reason,
            )
        )

    def handle_approval_timeout(self, tenant_id: TenantId, now: datetime) -> str:
        """Handle expired human approval gate. Returns 'proceed' or 'abort'."""
        self._assert_tenant(tenant_id)
        if self.pending_approval_gate is None:
            raise NoApprovalGatePending(str(self.execution_id))
        gate = self.pending_approval_gate
        default = gate.default_on_timeout
        self.pending_approval_gate = None

        if default == "proceed":
            rec = self._find_record(gate.task_id)
            rec.mark_completed(TaskOutcome.SUCCESS, now)
            self._transition(ExecutionState.RUNNING)
            self._mutate()
            self._emit(
                ApprovalGateTimedOutProceeded(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=str(tenant_id),
                    aggregate_id=str(self.execution_id),
                    aggregate_type="TaskGraphExecution",
                    task_id=str(gate.task_id),
                    gate_timeout_seconds=gate.gate_timeout_seconds,
                )
            )
        else:
            rec = self._find_record(gate.task_id)
            rec.mark_failed("Approval gate timed out with default_on_timeout=abort", now)
            self._transition(ExecutionState.PAUSED)
            self._mutate()

        return default

    def pause(self, tenant_id: TenantId, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.state not in {ExecutionState.RUNNING, ExecutionState.WAITING_FOR_APPROVAL}:
            raise InvalidStateTransition(self.state.value, "pause", str(self.execution_id))
        self._transition(ExecutionState.PAUSED)
        self._mutate()

    def resume(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.state != ExecutionState.PAUSED:
            raise InvalidStateTransition(self.state.value, "resume", str(self.execution_id))
        self._transition(ExecutionState.RUNNING)
        self._mutate()

    def initiate_rollback(
        self,
        tenant_id: TenantId,
        trigger_reason: str,
        rollback_task_count: int,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.state not in {ExecutionState.PAUSED, ExecutionState.FAILED}:
            raise RollbackNotAllowed(self.state.value)
        self._transition(ExecutionState.ROLLING_BACK)
        self._mutate()
        self._emit(
            RollbackInitiated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(self.execution_id),
                aggregate_type="TaskGraphExecution",
                trigger_reason=trigger_reason,
                task_count_to_rollback=rollback_task_count,
            )
        )

    def record_task_rolled_back(
        self,
        tenant_id: TenantId,
        task_id: CampaignTaskId,
        rollback_operation_ref: OperationRef,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        rec = self._find_record(task_id)
        rec.mark_rolled_back(rollback_operation_ref, now)
        self._mutate()
        self._emit(
            TaskRolledBack(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(self.execution_id),
                aggregate_type="TaskGraphExecution",
                task_id=str(task_id),
                rollback_operation_id=str(rollback_operation_ref.operation_id),
            )
        )

    def complete_rollback(self, tenant_id: TenantId, rolled_back_count: int, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.state != ExecutionState.ROLLING_BACK:
            raise InvalidStateTransition(
                self.state.value, "complete_rollback", str(self.execution_id)
            )
        self._transition(ExecutionState.FAILED)
        self._mutate()
        self._emit(
            RollbackCompleted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(self.execution_id),
                aggregate_type="TaskGraphExecution",
                rolled_back_count=rolled_back_count,
            )
        )

    def complete(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.state != ExecutionState.RUNNING:
            raise InvalidStateTransition(self.state.value, "complete", str(self.execution_id))
        self._transition(ExecutionState.COMPLETED)
        self._mutate()
        completed = sum(
            1 for r in self.task_records if r.state == TaskExecutionState.COMPLETED
        )
        skipped = sum(
            1 for r in self.task_records if r.state == TaskExecutionState.SKIPPED
        )
        terminal_failed = {TaskExecutionState.FAILED, TaskExecutionState.TIMED_OUT}
        failed = sum(1 for r in self.task_records if r.state in terminal_failed)
        self._emit(
            ExecutionCompleted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(self.execution_id),
                aggregate_type="TaskGraphExecution",
                campaign_instance_id=str(self.campaign_instance_ref.instance_id),
                tasks_completed=completed,
                tasks_skipped=skipped,
                tasks_failed=failed,
            )
        )

    def fail(self, tenant_id: TenantId, failure_reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        allowed = {ExecutionState.RUNNING, ExecutionState.PAUSED, ExecutionState.ROLLING_BACK}
        if self.state not in allowed:
            raise InvalidStateTransition(self.state.value, "fail", str(self.execution_id))
        self._transition(ExecutionState.FAILED)
        self._mutate()
        self._emit(
            ExecutionFailed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(self.execution_id),
                aggregate_type="TaskGraphExecution",
                campaign_instance_id=str(self.campaign_instance_ref.instance_id),
                failure_reason=failure_reason,
            )
        )

    def abort(self, tenant_id: TenantId, abort_reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        terminal = {ExecutionState.COMPLETED, ExecutionState.FAILED, ExecutionState.ABORTED}
        if self.state in terminal:
            raise InvalidStateTransition(self.state.value, "abort", str(self.execution_id))
        self.state = ExecutionState.ABORTED
        self._mutate()
        self._emit(
            ExecutionAborted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(self.execution_id),
                aggregate_type="TaskGraphExecution",
                campaign_instance_id=str(self.campaign_instance_ref.instance_id),
                abort_reason=abort_reason,
            )
        )

    def breach_safety_policy(
        self,
        tenant_id: TenantId,
        breach_type: str,
        details: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._emit(
            SafetyPolicyBreached(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(self.execution_id),
                aggregate_type="TaskGraphExecution",
                breach_type=breach_type,
                details=details,
                auto_abort_triggered=True,
            )
        )

    def all_tasks_terminal(self) -> bool:
        return all(r.is_terminal for r in self.task_records)
