"""Application service tests for ExecutionApplicationService."""

from __future__ import annotations

from uuid import uuid4

import pytest

from campaignexecution.application.commands.execution_commands import (
    AbortExecutionCommand,
    DispatchNextTasksCommand,
    InitializeCampaignExecutionCommand,
    InitiateRollbackCommand,
    PauseCampaignExecutionCommand,
    RecordTaskCompletionCommand,
    RecordTaskFailureCommand,
    ResumeCampaignExecutionCommand,
    TriggerAutoAbortOnDetectionCommand,
)
from campaignexecution.application.services.execution_application_service import (
    ExecutionApplicationService,
)
from campaignexecution.infrastructure.acl.degraded_adapters import (
    StubAttackActionQueryAdapter,
    StubOperationCreationAdapter,
)
from redforge.shared.identifiers import EntityId
from tests.campaignexecution.fakes.repos import FakeEventPublisher, FakeUnitOfWork


def make_service(uow: FakeUnitOfWork, publisher: FakeEventPublisher) -> ExecutionApplicationService:
    from campaignexecution.infrastructure.acl.degraded_adapters import StubNotificationAdapter

    op_port = StubOperationCreationAdapter()
    action_port = StubAttackActionQueryAdapter()
    return ExecutionApplicationService(
        uow_factory=lambda: uow,
        event_publisher=publisher,
        operation_creation_port=op_port,
        attack_action_query_port=action_port,
        notification_port=StubNotificationAdapter(),
    )


@pytest.fixture()
def uow() -> FakeUnitOfWork:
    return FakeUnitOfWork()


@pytest.fixture()
def publisher() -> FakeEventPublisher:
    return FakeEventPublisher()


@pytest.fixture()
def service(uow: FakeUnitOfWork, publisher: FakeEventPublisher) -> ExecutionApplicationService:
    return make_service(uow, publisher)


@pytest.fixture()
def tenant_id() -> object:
    return EntityId.generate()


# ── Initialization ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_initialize_execution_creates_dto(
    service: ExecutionApplicationService,
    tenant_id: object,
) -> None:
    task_ids = [uuid4(), uuid4()]
    cmd = InitializeCampaignExecutionCommand(
        tenant_id=tenant_id,  # type: ignore[arg-type]
        campaign_instance_id=uuid4(),
        campaign_id=uuid4(),
        graph_id=uuid4(),
        graph_version="1.0.0",
        engagement_id=uuid4(),
        task_ids=task_ids,
    )
    dto = await service.initialize_execution(cmd)
    assert dto.state == "Running"
    assert len(dto.task_records) == 2
    assert all(r.state == "Pending" for r in dto.task_records)


@pytest.mark.asyncio
async def test_initialize_publishes_events(
    service: ExecutionApplicationService,
    publisher: FakeEventPublisher,
    tenant_id: object,
) -> None:

    cmd = InitializeCampaignExecutionCommand(
        tenant_id=tenant_id,  # type: ignore[arg-type]
        campaign_instance_id=uuid4(),
        campaign_id=uuid4(),
        graph_id=uuid4(),
        graph_version="1.0.0",
        engagement_id=uuid4(),
        task_ids=[uuid4()],
    )
    await service.initialize_execution(cmd)
    types = {type(e).__name__ for e in publisher.published}
    assert "TaskGraphExecutionInitialized" in types
    assert "SafetyMonitorInitialized" in types


# ── Dispatch ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dispatch_task_returns_running_state(
    service: ExecutionApplicationService,
    uow: FakeUnitOfWork,
    tenant_id: object,
) -> None:
    task_id = uuid4()
    init_cmd = InitializeCampaignExecutionCommand(
        tenant_id=tenant_id,  # type: ignore[arg-type]
        campaign_instance_id=uuid4(),
        campaign_id=uuid4(),
        graph_id=uuid4(),
        graph_version="1.0.0",
        engagement_id=uuid4(),
        task_ids=[task_id],
    )
    init_dto = await service.initialize_execution(init_cmd)
    exec_id = init_dto.execution_id

    # Mark task ready first (simulate orchestrator marking tasks ready)
    from uuid import UUID

    from campaignexecution.domain.value_objects.identifiers import (
        CampaignTaskId,
        TaskGraphExecutionId,
    )

    execution = await uow.executions.find_by_id(
        TaskGraphExecutionId(UUID(exec_id)),
        tenant_id,  # type: ignore[arg-type]
    )
    assert execution is not None
    from datetime import UTC, datetime

    execution.mark_task_ready(tenant_id, CampaignTaskId(task_id), datetime.now(UTC))  # type: ignore[arg-type]

    dispatch_cmd = DispatchNextTasksCommand(
        tenant_id=tenant_id,  # type: ignore[arg-type]
        execution_id=UUID(exec_id),
        task_id=task_id,
        technique_id="T1059.001",
        technique_name="PowerShell",
    )
    dto = await service.dispatch_next_task(dispatch_cmd)
    rec = next(r for r in dto.task_records if r.task_id == str(task_id))
    assert rec.state == "Running"
    assert rec.operation_id is not None


# ── Task completion ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_record_task_completion(
    service: ExecutionApplicationService,
    uow: FakeUnitOfWork,
    tenant_id: object,
) -> None:
    from datetime import UTC, datetime
    from uuid import UUID

    from campaignexecution.domain.value_objects.execution_vos import OperationRef
    from campaignexecution.domain.value_objects.identifiers import (
        CampaignTaskId,
        TaskGraphExecutionId,
    )

    task_id = uuid4()
    init_cmd = InitializeCampaignExecutionCommand(
        tenant_id=tenant_id,  # type: ignore[arg-type]
        campaign_instance_id=uuid4(),
        campaign_id=uuid4(),
        graph_id=uuid4(),
        graph_version="1.0.0",
        engagement_id=uuid4(),
        task_ids=[task_id],
    )
    dto = await service.initialize_execution(init_cmd)
    exec_id = UUID(dto.execution_id)

    execution = await uow.executions.find_by_id(
        TaskGraphExecutionId(exec_id),
        tenant_id,  # type: ignore[arg-type]
    )
    assert execution is not None
    t = CampaignTaskId(task_id)
    execution.mark_task_ready(tenant_id, t, datetime.now(UTC))  # type: ignore[arg-type]
    op_ref = OperationRef(operation_id=uuid4(), tenant_id=tenant_id)  # type: ignore[arg-type]
    execution.record_task_dispatched(tenant_id, t, op_ref, datetime.now(UTC))  # type: ignore[arg-type]

    complete_cmd = RecordTaskCompletionCommand(
        tenant_id=tenant_id,  # type: ignore[arg-type]
        execution_id=exec_id,
        task_id=task_id,
        outcome="Success",
    )
    result_dto = await service.record_task_completion(complete_cmd)
    rec = next(r for r in result_dto.task_records if r.task_id == str(task_id))
    assert rec.state == "Completed"
    assert rec.outcome == "Success"


# ── Task failure ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_record_task_failure(
    service: ExecutionApplicationService,
    uow: FakeUnitOfWork,
    tenant_id: object,
) -> None:
    from datetime import UTC, datetime
    from uuid import UUID

    from campaignexecution.domain.value_objects.execution_vos import OperationRef
    from campaignexecution.domain.value_objects.identifiers import (
        CampaignTaskId,
        TaskGraphExecutionId,
    )

    task_id = uuid4()
    init_cmd = InitializeCampaignExecutionCommand(
        tenant_id=tenant_id,  # type: ignore[arg-type]
        campaign_instance_id=uuid4(),
        campaign_id=uuid4(),
        graph_id=uuid4(),
        graph_version="1.0.0",
        engagement_id=uuid4(),
        task_ids=[task_id],
    )
    dto = await service.initialize_execution(init_cmd)
    exec_id = UUID(dto.execution_id)

    execution = await uow.executions.find_by_id(
        TaskGraphExecutionId(exec_id),
        tenant_id,  # type: ignore[arg-type]
    )
    assert execution is not None
    t = CampaignTaskId(task_id)
    execution.mark_task_ready(tenant_id, t, datetime.now(UTC))  # type: ignore[arg-type]
    op_ref = OperationRef(operation_id=uuid4(), tenant_id=tenant_id)  # type: ignore[arg-type]
    execution.record_task_dispatched(tenant_id, t, op_ref, datetime.now(UTC))  # type: ignore[arg-type]

    fail_cmd = RecordTaskFailureCommand(
        tenant_id=tenant_id,  # type: ignore[arg-type]
        execution_id=exec_id,
        task_id=task_id,
        failure_reason="M29 operation failed",
    )
    result_dto = await service.record_task_failure(fail_cmd)
    rec = next(r for r in result_dto.task_records if r.task_id == str(task_id))
    assert rec.state == "Failed"


# ── Pause and resume ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pause_and_resume_execution(
    service: ExecutionApplicationService,
    tenant_id: object,
) -> None:
    from uuid import UUID

    init_cmd = InitializeCampaignExecutionCommand(
        tenant_id=tenant_id,  # type: ignore[arg-type]
        campaign_instance_id=uuid4(),
        campaign_id=uuid4(),
        graph_id=uuid4(),
        graph_version="1.0.0",
        engagement_id=uuid4(),
        task_ids=[uuid4()],
    )
    dto = await service.initialize_execution(init_cmd)
    exec_id = UUID(dto.execution_id)

    pause_dto = await service.pause_execution(
        PauseCampaignExecutionCommand(
            tenant_id=tenant_id,  # type: ignore[arg-type]
            execution_id=exec_id,
            reason="manual pause",
        )
    )
    assert pause_dto.state == "Paused"

    resume_dto = await service.resume_execution(
        ResumeCampaignExecutionCommand(
            tenant_id=tenant_id,  # type: ignore[arg-type]
            execution_id=exec_id,
        )
    )
    assert resume_dto.state == "Running"


# ── Not found ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_execution_not_found_returns_none(
    service: ExecutionApplicationService,
    tenant_id: object,
) -> None:
    from campaignexecution.application.commands.execution_commands import GetExecutionQuery

    result = await service.get_execution(
        GetExecutionQuery(tenant_id=tenant_id, execution_id=uuid4())  # type: ignore[arg-type]
    )
    assert result is None


# ── Auto-abort on detection ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_auto_abort_on_detection(
    service: ExecutionApplicationService,
    tenant_id: object,
) -> None:
    instance_id = uuid4()
    init_cmd = InitializeCampaignExecutionCommand(
        tenant_id=tenant_id,  # type: ignore[arg-type]
        campaign_instance_id=instance_id,
        campaign_id=uuid4(),
        graph_id=uuid4(),
        graph_version="1.0.0",
        engagement_id=uuid4(),
        task_ids=[uuid4()],
        auto_abort_on_detection=True,
    )
    await service.initialize_execution(init_cmd)

    monitor_dto = await service.trigger_auto_abort_on_detection(
        TriggerAutoAbortOnDetectionCommand(
            tenant_id=tenant_id,  # type: ignore[arg-type]
            campaign_instance_id=instance_id,
            detection_detail="DetectionFinding-XYZ",
        )
    )
    assert monitor_dto is not None
    assert monitor_dto.auto_abort_triggered


# ── Abort ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_abort_execution(
    service: ExecutionApplicationService,
    tenant_id: object,
) -> None:
    from uuid import UUID

    init_cmd = InitializeCampaignExecutionCommand(
        tenant_id=tenant_id,  # type: ignore[arg-type]
        campaign_instance_id=uuid4(),
        campaign_id=uuid4(),
        graph_id=uuid4(),
        graph_version="1.0.0",
        engagement_id=uuid4(),
        task_ids=[uuid4()],
    )
    dto = await service.initialize_execution(init_cmd)

    abort_dto = await service.abort_execution(
        AbortExecutionCommand(
            tenant_id=tenant_id,  # type: ignore[arg-type]
            execution_id=UUID(dto.execution_id),
            abort_reason="M29 kill switch triggered",
        )
    )
    assert abort_dto.state == "Aborted"


# ── Rollback ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_initiate_rollback_from_paused(
    service: ExecutionApplicationService,
    tenant_id: object,
) -> None:
    from uuid import UUID

    init_cmd = InitializeCampaignExecutionCommand(
        tenant_id=tenant_id,  # type: ignore[arg-type]
        campaign_instance_id=uuid4(),
        campaign_id=uuid4(),
        graph_id=uuid4(),
        graph_version="1.0.0",
        engagement_id=uuid4(),
        task_ids=[uuid4()],
    )
    dto = await service.initialize_execution(init_cmd)
    exec_id = UUID(dto.execution_id)

    await service.pause_execution(
        PauseCampaignExecutionCommand(
            tenant_id=tenant_id,  # type: ignore[arg-type]
            execution_id=exec_id,
            reason="safety breach",
        )
    )
    rollback_dto = await service.initiate_rollback(
        InitiateRollbackCommand(
            tenant_id=tenant_id,  # type: ignore[arg-type]
            execution_id=exec_id,
            trigger_reason="manual rollback",
        )
    )
    assert rollback_dto.state == "RollingBack"


# ── Phase 3 wiring: branch resolution, kill switch, approval, parallel ────────


@pytest.mark.asyncio
async def test_record_completion_uses_branch_resolution_service(
    service: ExecutionApplicationService,
    uow: FakeUnitOfWork,
    publisher: FakeEventPublisher,
    tenant_id: object,
) -> None:
    from datetime import UTC, datetime
    from uuid import UUID

    from campaignexecution.application.commands.execution_commands import (
        SuccessorPredicateSpec,
    )
    from campaignexecution.domain.value_objects.execution_vos import OperationRef
    from campaignexecution.domain.value_objects.identifiers import (
        CampaignTaskId,
        TaskGraphExecutionId,
    )

    task_a = uuid4()
    task_ok = uuid4()
    task_fail = uuid4()
    init_dto = await service.initialize_execution(
        InitializeCampaignExecutionCommand(
            tenant_id=tenant_id,  # type: ignore[arg-type]
            campaign_instance_id=uuid4(),
            campaign_id=uuid4(),
            graph_id=uuid4(),
            graph_version="1.0.0",
            engagement_id=uuid4(),
            task_ids=[task_a, task_ok, task_fail],
        )
    )
    exec_id = UUID(init_dto.execution_id)
    execution = await uow.executions.find_by_id(
        TaskGraphExecutionId(exec_id),
        tenant_id,  # type: ignore[arg-type]
    )
    assert execution is not None
    tid = tenant_id  # type: ignore[arg-type]
    now = datetime.now(UTC)
    execution.mark_task_ready(tid, CampaignTaskId(task_a), now)
    execution.record_task_dispatched(
        tid,
        CampaignTaskId(task_a),
        OperationRef(operation_id=uuid4(), tenant_id=tenant_id),  # type: ignore[arg-type]
        now,
    )

    dto = await service.record_task_completion(
        RecordTaskCompletionCommand(
            tenant_id=tenant_id,  # type: ignore[arg-type]
            execution_id=exec_id,
            task_id=task_a,
            outcome="Success",
            successors=(
                SuccessorPredicateSpec(task_id=task_ok, predicate="ExecuteOnSuccess"),
                SuccessorPredicateSpec(task_id=task_fail, predicate="ExecuteOnFailure"),
            ),
        )
    )
    by_id = {r.task_id: r.state for r in dto.task_records}
    assert by_id[str(task_ok)] == "ReadyToDispatch"
    assert by_id[str(task_fail)] == "Skipped"
    assert any(type(e).__name__ == "ConditionalBranchResolved" for e in publisher.published)


@pytest.mark.asyncio
async def test_kill_switch_pauses_running_execution(
    service: ExecutionApplicationService,
    tenant_id: object,
) -> None:
    from uuid import UUID

    from campaignexecution.application.commands.execution_commands import (
        HandleKillSwitchTriggeredCommand,
    )

    dto = await service.initialize_execution(
        InitializeCampaignExecutionCommand(
            tenant_id=tenant_id,  # type: ignore[arg-type]
            campaign_instance_id=uuid4(),
            campaign_id=uuid4(),
            graph_id=uuid4(),
            graph_version="1.0.0",
            engagement_id=uuid4(),
            task_ids=[uuid4()],
        )
    )
    paused = await service.handle_kill_switch_triggered(
        HandleKillSwitchTriggeredCommand(
            tenant_id=tenant_id,  # type: ignore[arg-type]
            execution_id=UUID(dto.execution_id),
        )
    )
    assert paused.state == "Paused"


@pytest.mark.asyncio
async def test_reach_human_approval_gate_notifies(
    service: ExecutionApplicationService,
    tenant_id: object,
) -> None:
    from uuid import UUID

    from campaignexecution.application.commands.execution_commands import (
        ReachHumanApprovalGateCommand,
    )
    from campaignexecution.infrastructure.acl.degraded_adapters import StubNotificationAdapter

    # Rebuild service with shared notification stub
    assert isinstance(service._notification_port, StubNotificationAdapter)
    notify = service._notification_port
    task_id = uuid4()
    dto = await service.initialize_execution(
        InitializeCampaignExecutionCommand(
            tenant_id=tenant_id,  # type: ignore[arg-type]
            campaign_instance_id=uuid4(),
            campaign_id=uuid4(),
            graph_id=uuid4(),
            graph_version="1.0.0",
            engagement_id=uuid4(),
            task_ids=[task_id],
        )
    )
    result = await service.reach_human_approval_gate(
        ReachHumanApprovalGateCommand(
            tenant_id=tenant_id,  # type: ignore[arg-type]
            execution_id=UUID(dto.execution_id),
            task_id=task_id,
            gate_timeout_seconds=60,
            required_approver_role="campaign_approver",
            default_on_timeout="abort",
        )
    )
    assert result.state == "WaitingForApproval"
    assert len(notify.approval_gates) == 1


@pytest.mark.asyncio
async def test_parallel_dispatch_emits_track_started(
    service: ExecutionApplicationService,
    uow: FakeUnitOfWork,
    publisher: FakeEventPublisher,
    tenant_id: object,
) -> None:
    from datetime import UTC, datetime
    from uuid import UUID

    from campaignexecution.application.commands.execution_commands import DispatchTaskSpec
    from campaignexecution.domain.value_objects.identifiers import (
        CampaignTaskId,
        TaskGraphExecutionId,
    )

    t1, t2 = uuid4(), uuid4()
    dto = await service.initialize_execution(
        InitializeCampaignExecutionCommand(
            tenant_id=tenant_id,  # type: ignore[arg-type]
            campaign_instance_id=uuid4(),
            campaign_id=uuid4(),
            graph_id=uuid4(),
            graph_version="1.0.0",
            engagement_id=uuid4(),
            task_ids=[t1, t2],
        )
    )
    exec_id = UUID(dto.execution_id)
    execution = await uow.executions.find_by_id(
        TaskGraphExecutionId(exec_id),
        tenant_id,  # type: ignore[arg-type]
    )
    assert execution is not None
    tid = tenant_id  # type: ignore[arg-type]
    now = datetime.now(UTC)
    execution.mark_task_ready(tid, CampaignTaskId(t1), now)
    execution.mark_task_ready(tid, CampaignTaskId(t2), now)

    await service.dispatch_next_task(
        DispatchNextTasksCommand(
            tenant_id=tenant_id,  # type: ignore[arg-type]
            execution_id=exec_id,
            tasks=(
                DispatchTaskSpec(task_id=t1, technique_id="T1", technique_name="A"),
                DispatchTaskSpec(task_id=t2, technique_id="T2", technique_name="B"),
            ),
        )
    )
    assert any(type(e).__name__ == "ExecutionTrackStarted" for e in publisher.published)
