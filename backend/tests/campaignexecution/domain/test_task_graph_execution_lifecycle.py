"""Tests for TaskGraphExecution aggregate lifecycle and state machine."""

from __future__ import annotations

import pytest

from campaignexecution.domain.aggregates.task_graph_execution import TaskGraphExecution
from campaignexecution.domain.exceptions.domain_exceptions import (
    BarrierNotPassable,
    NoApprovalGatePending,
    RollbackNotAllowed,
    TaskNotFound,
)
from campaignexecution.domain.value_objects.enums import (
    ExecutionState,
    TaskExecutionState,
    TaskOutcome,
)
from campaignexecution.domain.value_objects.execution_vos import (
    CampaignInstanceRef,
    EngagementRef,
    OperationRef,
    PendingApprovalGate,
    PolicySnapshot,
    TaskGraphVersionRef,
)
from campaignexecution.domain.value_objects.identifiers import (
    CampaignTaskId,
    TaskGraphExecutionId,
    TenantId,
)


def make_execution(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> TaskGraphExecution:
    from datetime import UTC, datetime

    now_dt = now if isinstance(now, datetime) else datetime.now(UTC)
    exec_id = TaskGraphExecutionId.generate()
    return TaskGraphExecution.initialize(
        execution_id=exec_id,
        tenant_id=tenant_id,
        campaign_instance_ref=campaign_instance_ref,
        graph_version_ref=graph_version_ref,
        engagement_ref=engagement_ref,
        policy_snapshot=policy_snapshot,
        task_ids=task_ids,
        now=now_dt,
    )


# ── Initialization ─────────────────────────────────────────────────────────────

def test_initialization_creates_pending_records(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    assert len(execution.task_records) == 3
    for rec in execution.task_records:
        assert rec.state == TaskExecutionState.PENDING


def test_initialization_emits_initialized_event(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from campaignexecution.domain.events.execution_events import TaskGraphExecutionInitialized

    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    events = execution.pop_events()
    assert any(isinstance(e, TaskGraphExecutionInitialized) for e in events)


def test_initialization_starts_in_initializing_state(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    # mark_running transitions to RUNNING
    from datetime import UTC, datetime
    execution.mark_running(datetime.now(UTC))
    assert execution.state == ExecutionState.RUNNING


# ── Dispatch ───────────────────────────────────────────────────────────────────

def test_dispatch_task_transitions_to_running(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime
    from uuid import uuid4

    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    execution.mark_running(datetime.now(UTC))

    task = task_ids[0]
    execution.mark_task_ready(tenant_id, task, datetime.now(UTC))

    op_ref = OperationRef(operation_id=uuid4(), tenant_id=tenant_id.value)
    execution.record_task_dispatched(tenant_id, task, op_ref, datetime.now(UTC))

    rec = next(r for r in execution.task_records if r.task_id == task)
    assert rec.state == TaskExecutionState.RUNNING
    assert rec.operation_ref == op_ref


def test_dispatch_is_idempotent(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime
    from uuid import uuid4

    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    execution.mark_running(datetime.now(UTC))

    task = task_ids[0]
    execution.mark_task_ready(tenant_id, task, datetime.now(UTC))

    op_ref = OperationRef(operation_id=uuid4(), tenant_id=tenant_id.value)
    execution.record_task_dispatched(tenant_id, task, op_ref, datetime.now(UTC))
    # Second dispatch should be silently ignored (idempotent)
    execution.record_task_dispatched(tenant_id, task, op_ref, datetime.now(UTC))

    running_count = sum(1 for r in execution.task_records if r.state == TaskExecutionState.RUNNING)
    assert running_count == 1


# ── Completion ─────────────────────────────────────────────────────────────────

def test_task_completion_marks_state(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime
    from uuid import uuid4

    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    execution.mark_running(datetime.now(UTC))
    task = task_ids[0]
    execution.mark_task_ready(tenant_id, task, datetime.now(UTC))
    op_ref = OperationRef(operation_id=uuid4(), tenant_id=tenant_id.value)
    execution.record_task_dispatched(tenant_id, task, op_ref, datetime.now(UTC))
    execution.record_task_completion(tenant_id, task, TaskOutcome.SUCCESS, datetime.now(UTC))

    rec = next(r for r in execution.task_records if r.task_id == task)
    assert rec.state == TaskExecutionState.COMPLETED
    assert rec.outcome == TaskOutcome.SUCCESS


def test_task_completion_is_idempotent(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime
    from uuid import uuid4

    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    execution.mark_running(datetime.now(UTC))
    task = task_ids[0]
    execution.mark_task_ready(tenant_id, task, datetime.now(UTC))
    op_ref = OperationRef(operation_id=uuid4(), tenant_id=tenant_id.value)
    execution.record_task_dispatched(tenant_id, task, op_ref, datetime.now(UTC))
    execution.record_task_completion(tenant_id, task, TaskOutcome.SUCCESS, datetime.now(UTC))
    # Second call should not raise
    execution.record_task_completion(tenant_id, task, TaskOutcome.FAILURE, datetime.now(UTC))

    rec = next(r for r in execution.task_records if r.task_id == task)
    # First outcome should stick
    assert rec.outcome == TaskOutcome.SUCCESS


# ── Conditional branch ─────────────────────────────────────────────────────────

def test_completion_with_successors_marks_ready_and_skipped(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime
    from uuid import uuid4

    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    execution.mark_running(datetime.now(UTC))

    t0, t1, t2 = task_ids
    execution.mark_task_ready(tenant_id, t0, datetime.now(UTC))
    op_ref = OperationRef(operation_id=uuid4(), tenant_id=tenant_id.value)
    execution.record_task_dispatched(tenant_id, t0, op_ref, datetime.now(UTC))
    execution.record_task_completion(
        tenant_id, t0, TaskOutcome.SUCCESS, datetime.now(UTC),
        ready_successor_ids=[t1],
        skipped_successor_ids=[t2],
    )

    rec1 = next(r for r in execution.task_records if r.task_id == t1)
    rec2 = next(r for r in execution.task_records if r.task_id == t2)
    assert rec1.state == TaskExecutionState.READY_TO_DISPATCH
    assert rec2.state == TaskExecutionState.SKIPPED


# ── Barrier evaluation ─────────────────────────────────────────────────────────

def test_barrier_passes_when_all_group_tasks_done(
    tenant_id: TenantId,
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime
    from uuid import uuid4

    t1 = CampaignTaskId(uuid4())
    t2 = CampaignTaskId(uuid4())
    barrier = CampaignTaskId(uuid4())

    execution = make_execution(
        tenant_id, [t1, t2, barrier], campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    execution.mark_running(datetime.now(UTC))

    # Dispatch and complete t1 and t2
    for task in [t1, t2]:
        execution.mark_task_ready(tenant_id, task, datetime.now(UTC))
        op_ref = OperationRef(operation_id=uuid4(), tenant_id=tenant_id.value)
        execution.record_task_dispatched(tenant_id, task, op_ref, datetime.now(UTC))
        execution.record_task_completion(tenant_id, task, TaskOutcome.SUCCESS, datetime.now(UTC))

    # Barrier should pass
    execution.evaluate_barrier(tenant_id, barrier, [t1, t2], datetime.now(UTC))
    barrier_rec = next(r for r in execution.task_records if r.task_id == barrier)
    assert barrier_rec.state == TaskExecutionState.READY_TO_DISPATCH


def test_barrier_blocks_when_tasks_pending(
    tenant_id: TenantId,
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime
    from uuid import uuid4

    t1 = CampaignTaskId(uuid4())
    t2 = CampaignTaskId(uuid4())
    barrier = CampaignTaskId(uuid4())

    execution = make_execution(
        tenant_id, [t1, t2, barrier], campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    execution.mark_running(datetime.now(UTC))

    # Only complete t1
    execution.mark_task_ready(tenant_id, t1, datetime.now(UTC))
    op_ref = OperationRef(operation_id=uuid4(), tenant_id=tenant_id.value)
    execution.record_task_dispatched(tenant_id, t1, op_ref, datetime.now(UTC))
    execution.record_task_completion(tenant_id, t1, TaskOutcome.SUCCESS, datetime.now(UTC))

    with pytest.raises(BarrierNotPassable):
        execution.evaluate_barrier(tenant_id, barrier, [t1, t2], datetime.now(UTC))


# ── Human approval gate ────────────────────────────────────────────────────────

def test_approval_gate_transitions_to_waiting(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime

    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    execution.mark_running(datetime.now(UTC))

    gate = PendingApprovalGate(
        task_id=task_ids[0],
        gate_created_at=datetime.now(UTC),
        gate_timeout_seconds=300,
        required_approver_role="campaign:approver",
        default_on_timeout="abort",
    )
    execution.reach_human_approval_gate(tenant_id, gate, datetime.now(UTC))
    assert execution.state == ExecutionState.WAITING_FOR_APPROVAL
    assert execution.pending_approval_gate == gate


def test_grant_approval_transitions_back_to_running(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime
    from uuid import uuid4

    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    execution.mark_running(datetime.now(UTC))

    # Make the approval task running first
    task = task_ids[0]
    execution.mark_task_ready(tenant_id, task, datetime.now(UTC))
    op_ref = OperationRef(operation_id=uuid4(), tenant_id=tenant_id.value)
    execution.record_task_dispatched(tenant_id, task, op_ref, datetime.now(UTC))

    gate = PendingApprovalGate(
        task_id=task,
        gate_created_at=datetime.now(UTC),
        gate_timeout_seconds=300,
        required_approver_role="campaign:approver",
        default_on_timeout="abort",
    )
    execution.reach_human_approval_gate(tenant_id, gate, datetime.now(UTC))
    execution.grant_human_approval(tenant_id, "approver-001", datetime.now(UTC))
    assert execution.state == ExecutionState.RUNNING
    assert execution.pending_approval_gate is None


def test_deny_approval_transitions_to_paused(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime
    from uuid import uuid4

    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    execution.mark_running(datetime.now(UTC))

    task = task_ids[0]
    execution.mark_task_ready(tenant_id, task, datetime.now(UTC))
    op_ref = OperationRef(operation_id=uuid4(), tenant_id=tenant_id.value)
    execution.record_task_dispatched(tenant_id, task, op_ref, datetime.now(UTC))

    gate = PendingApprovalGate(
        task_id=task,
        gate_created_at=datetime.now(UTC),
        gate_timeout_seconds=300,
        required_approver_role="campaign:approver",
        default_on_timeout="abort",
    )
    execution.reach_human_approval_gate(tenant_id, gate, datetime.now(UTC))
    execution.deny_human_approval(tenant_id, "approver-001", "Not yet authorized", datetime.now(UTC))
    assert execution.state == ExecutionState.PAUSED


def test_approval_timeout_default_abort_pauses(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime
    from uuid import uuid4

    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    execution.mark_running(datetime.now(UTC))

    task = task_ids[0]
    execution.mark_task_ready(tenant_id, task, datetime.now(UTC))
    op_ref = OperationRef(operation_id=uuid4(), tenant_id=tenant_id.value)
    execution.record_task_dispatched(tenant_id, task, op_ref, datetime.now(UTC))

    gate = PendingApprovalGate(
        task_id=task,
        gate_created_at=datetime.now(UTC),
        gate_timeout_seconds=1,
        required_approver_role="campaign:approver",
        default_on_timeout="abort",
    )
    execution.reach_human_approval_gate(tenant_id, gate, datetime.now(UTC))
    result = execution.handle_approval_timeout(tenant_id, datetime.now(UTC))
    assert result == "abort"
    assert execution.state == ExecutionState.PAUSED


def test_approval_timeout_default_proceed_continues(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime
    from uuid import uuid4

    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    execution.mark_running(datetime.now(UTC))

    task = task_ids[0]
    execution.mark_task_ready(tenant_id, task, datetime.now(UTC))
    op_ref = OperationRef(operation_id=uuid4(), tenant_id=tenant_id.value)
    execution.record_task_dispatched(tenant_id, task, op_ref, datetime.now(UTC))

    gate = PendingApprovalGate(
        task_id=task,
        gate_created_at=datetime.now(UTC),
        gate_timeout_seconds=1,
        required_approver_role="campaign:approver",
        default_on_timeout="proceed",
    )
    execution.reach_human_approval_gate(tenant_id, gate, datetime.now(UTC))
    result = execution.handle_approval_timeout(tenant_id, datetime.now(UTC))
    assert result == "proceed"
    assert execution.state == ExecutionState.RUNNING


def test_no_approval_gate_raises(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime

    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    execution.mark_running(datetime.now(UTC))
    with pytest.raises(NoApprovalGatePending):
        execution.grant_human_approval(tenant_id, "approver", datetime.now(UTC))


# ── Rollback ───────────────────────────────────────────────────────────────────

def test_rollback_requires_paused_or_failed(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime

    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    execution.mark_running(datetime.now(UTC))

    with pytest.raises(RollbackNotAllowed):
        execution.initiate_rollback(tenant_id, "test", 0, datetime.now(UTC))


def test_rollback_proceeds_from_paused(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime

    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    execution.mark_running(datetime.now(UTC))
    execution.pause(tenant_id, "manual", datetime.now(UTC))
    execution.initiate_rollback(tenant_id, "manual rollback", 0, datetime.now(UTC))
    assert execution.state == ExecutionState.ROLLING_BACK


# ── Task not found ─────────────────────────────────────────────────────────────

def test_task_not_found_raises(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime
    from uuid import uuid4

    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    unknown_task = CampaignTaskId(uuid4())
    with pytest.raises(TaskNotFound):
        execution.record_task_failure(tenant_id, unknown_task, "not found", datetime.now(UTC))


# ── Complete and fail ──────────────────────────────────────────────────────────

def test_complete_from_running(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime

    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    execution.mark_running(datetime.now(UTC))
    execution.complete(tenant_id, datetime.now(UTC))
    assert execution.state == ExecutionState.COMPLETED


def test_abort_from_any_non_terminal(
    tenant_id: TenantId,
    task_ids: list[CampaignTaskId],
    campaign_instance_ref: CampaignInstanceRef,
    graph_version_ref: TaskGraphVersionRef,
    engagement_ref: EngagementRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime

    execution = make_execution(
        tenant_id, task_ids, campaign_instance_ref, graph_version_ref, engagement_ref, policy_snapshot, now
    )
    execution.mark_running(datetime.now(UTC))
    execution.abort(tenant_id, "force abort", datetime.now(UTC))
    assert execution.state == ExecutionState.ABORTED
