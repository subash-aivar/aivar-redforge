"""ExecutionApplicationService — orchestrates TaskGraphExecution lifecycle."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import uuid7

from campaignexecution.application.dtos.execution_dtos import (
    ExecutionDTO,
    SafetyMonitorDTO,
    TaskExecutionRecordDTO,
)
from campaignexecution.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from campaignexecution.domain.aggregates.campaign_safety_monitor import CampaignSafetyMonitor
from campaignexecution.domain.aggregates.task_graph_execution import TaskGraphExecution
from campaignexecution.domain.services.branch_resolution_service import BranchResolutionService
from campaignexecution.domain.services.campaign_pause_coordinator import CampaignPauseCoordinator
from campaignexecution.domain.services.rollback_executor import RollbackExecutor
from campaignexecution.domain.services.task_dispatch_service import TaskDispatchService
from campaignexecution.domain.value_objects.enums import TaskOutcome
from campaignexecution.domain.value_objects.execution_vos import (
    CampaignInstanceRef,
    EngagementRef,
    PendingApprovalGate,
    PolicySnapshot,
    TaskGraphVersionRef,
)
from campaignexecution.domain.value_objects.identifiers import (
    CampaignInstanceId,
    CampaignTaskId,
    SafetyMonitorId,
    TaskGraphExecutionId,
    TenantId,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from campaignexecution.application.commands.execution_commands import (
        AbortExecutionCommand,
        CompleteExecutionCommand,
        DenyHumanApprovalCommand,
        DispatchNextTasksCommand,
        EvaluateBarrierCommand,
        GetExecutionQuery,
        GrantHumanApprovalCommand,
        HandleApprovalTimeoutCommand,
        HandleKillSwitchTriggeredCommand,
        InitializeCampaignExecutionCommand,
        InitiateRollbackCommand,
        PauseCampaignExecutionCommand,
        ReachHumanApprovalGateCommand,
        RecordTaskCompletionCommand,
        RecordTaskFailureCommand,
        ResolveConditionalBranchCommand,
        ResumeCampaignExecutionCommand,
        SuccessorPredicateSpec,
        TriggerAutoAbortOnDetectionCommand,
    )
    from campaignexecution.application.ports.i_event_publisher import IEventPublisher
    from campaignexecution.application.ports.i_unit_of_work import IUnitOfWork
    from campaignexecution.domain.events.base import BaseDomainEvent
    from campaignexecution.domain.ports.i_attack_action_query_port import IAttackActionQueryPort
    from campaignexecution.domain.ports.i_notification_port import INotificationPort
    from campaignexecution.domain.ports.i_operation_creation_port import IOperationCreationPort

log = logging.getLogger(__name__)


def _to_execution_dto(execution: TaskGraphExecution) -> ExecutionDTO:
    records = [
        TaskExecutionRecordDTO(
            task_id=str(r.task_id),
            state=r.state.value,
            outcome=r.outcome.value if r.outcome else None,
            operation_id=str(r.operation_ref.operation_id) if r.operation_ref else None,
            dispatched_at=r.dispatched_at,
            completed_at=r.completed_at,
            failure_reason=r.failure_reason,
        )
        for r in execution.task_records
    ]
    return ExecutionDTO(
        execution_id=str(execution.execution_id),
        tenant_id=str(execution.tenant_id),
        campaign_instance_id=str(execution.campaign_instance_ref.instance_id),
        graph_id=str(execution.graph_version_ref.graph_id),
        graph_version=execution.graph_version_ref.version_str,
        state=execution.state.value,
        concurrent_action_count=execution.concurrent_action_count(),
        task_records=records,
        pending_approval_gate_task_id=(
            str(execution.pending_approval_gate.task_id)
            if execution.pending_approval_gate
            else None
        ),
    )


def _to_monitor_dto(monitor: CampaignSafetyMonitor) -> SafetyMonitorDTO:
    return SafetyMonitorDTO(
        monitor_id=str(monitor.monitor_id),
        tenant_id=str(monitor.tenant_id),
        campaign_instance_id=str(monitor.campaign_instance_ref.instance_id),
        monitor_state=monitor.monitor_state.value,
        concurrent_action_count=monitor.concurrent_action_count,
        auto_abort_triggered=monitor.auto_abort_triggered,
        max_concurrent_actions=monitor.policy_snapshot.max_concurrent_actions,
    )


class ExecutionApplicationService:
    """Application service for TaskGraphExecution and CampaignSafetyMonitor lifecycle.

    Follows CQRS: commands mutate state; queries return DTOs.
    All commands: validate → load via UoW → call domain → save → commit → publish events.
    """

    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        operation_creation_port: IOperationCreationPort,
        attack_action_query_port: IAttackActionQueryPort,
        notification_port: INotificationPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher
        self._operation_port = operation_creation_port
        self._action_query_port = attack_action_query_port
        self._notification_port = notification_port
        self._dispatch_svc = TaskDispatchService()
        self._branch_svc = BranchResolutionService()
        self._pause_coordinator = CampaignPauseCoordinator()
        self._rollback_executor = RollbackExecutor()

    async def _publish(self, events: list[BaseDomainEvent]) -> None:
        if events:
            try:
                await self._event_publisher.publish_batch(events)
            except Exception:
                log.exception("Event publication failed — events discarded after commit")

    def _resolve_successors(
        self,
        execution: TaskGraphExecution,
        outcome: TaskOutcome,
        completed_task_id: CampaignTaskId,
        successors: tuple[SuccessorPredicateSpec, ...],
    ) -> tuple[list[CampaignTaskId], list[CampaignTaskId]]:
        specs = [(CampaignTaskId(s.task_id), s.predicate, s.objective_ref) for s in successors]
        return self._branch_svc.resolve(
            completed_task_id,
            outcome,
            specs,
            execution.objective_states,
        )

    async def initialize_execution(self, cmd: InitializeCampaignExecutionCommand) -> ExecutionDTO:
        now = datetime.now(UTC)
        tenant = TenantId(cmd.tenant_id)
        execution_id = TaskGraphExecutionId.generate()
        monitor_id = SafetyMonitorId.generate()

        campaign_instance_ref = CampaignInstanceRef(
            instance_id=cmd.campaign_instance_id,
            campaign_id=cmd.campaign_id,
            tenant_id=cmd.tenant_id,
        )
        graph_version_ref = TaskGraphVersionRef(
            graph_id=cmd.graph_id,
            version_str=cmd.graph_version,
        )
        engagement_ref = EngagementRef(
            engagement_id=cmd.engagement_id,
            tenant_id=cmd.tenant_id,
        )
        policy_snapshot = PolicySnapshot(
            max_concurrent_actions=cmd.max_concurrent_actions,
            auto_abort_on_detection=cmd.auto_abort_on_detection,
            auto_abort_on_objective_failure=cmd.auto_abort_on_objective_failure,
            blast_radius_ceiling=cmd.blast_radius_ceiling,
        )
        task_ids = [CampaignTaskId(tid) for tid in cmd.task_ids]

        execution = TaskGraphExecution.initialize(
            execution_id=execution_id,
            tenant_id=tenant,
            campaign_instance_ref=campaign_instance_ref,
            graph_version_ref=graph_version_ref,
            engagement_ref=engagement_ref,
            policy_snapshot=policy_snapshot,
            task_ids=task_ids,
            now=now,
        )
        monitor = CampaignSafetyMonitor.create(
            monitor_id=monitor_id,
            tenant_id=tenant,
            campaign_instance_ref=campaign_instance_ref,
            policy_snapshot=policy_snapshot,
            now=now,
        )
        execution.mark_running(now)

        async with self._uow_factory() as uow:
            await uow.executions.save(execution)
            await uow.safety_monitors.save(monitor)
            await uow.commit()

        all_events: list[BaseDomainEvent] = []
        all_events.extend(execution.pop_events())
        all_events.extend(monitor.pop_events())
        await self._publish(all_events)
        return _to_execution_dto(execution)

    async def dispatch_next_task(self, cmd: DispatchNextTasksCommand) -> ExecutionDTO:
        from campaignexecution.application.commands.execution_commands import DispatchTaskSpec

        now = datetime.now(UTC)
        tenant = TenantId(cmd.tenant_id)
        if cmd.tasks:
            specs = list(cmd.tasks)
        elif cmd.task_id is not None:
            specs = [
                DispatchTaskSpec(
                    task_id=cmd.task_id,
                    technique_id=cmd.technique_id,
                    technique_name=cmd.technique_name,
                    parameters=dict(cmd.parameters),
                )
            ]
        else:
            raise ApplicationValidationError("tasks", "Provide task_id or a non-empty tasks list")

        async with self._uow_factory() as uow:
            execution = await uow.executions.find_by_id(
                TaskGraphExecutionId(cmd.execution_id), tenant
            )
            if execution is None:
                raise ApplicationNotFoundError("TaskGraphExecution", str(cmd.execution_id))

            monitor = await uow.safety_monitors.find_by_campaign_instance(
                CampaignInstanceId(execution.campaign_instance_ref.instance_id), tenant
            )

            if len(specs) > 1:
                execution.start_execution_track(
                    tenant,
                    track_id=str(uuid7()),
                    task_ids=[CampaignTaskId(s.task_id) for s in specs],
                    now=now,
                )

            for spec in specs:
                task_id = CampaignTaskId(spec.task_id)
                if monitor is not None:
                    monitor.register_action(tenant, str(task_id), now)

                operation_ref = await self._dispatch_svc.dispatch(
                    tenant_id=tenant,
                    campaign_instance_id=CampaignInstanceId(
                        execution.campaign_instance_ref.instance_id
                    ),
                    task_id=task_id,
                    technique_id=spec.technique_id,
                    technique_name=spec.technique_name,
                    parameters=dict(spec.parameters),
                    engagement_ref=execution.engagement_ref,
                    port=self._operation_port,
                )
                execution.record_task_dispatched(tenant, task_id, operation_ref, now)

            await uow.executions.save(execution)
            if monitor is not None:
                await uow.safety_monitors.save(monitor)
            await uow.commit()

        all_events: list[BaseDomainEvent] = []
        all_events.extend(execution.pop_events())
        if monitor is not None:
            all_events.extend(monitor.pop_events())
        await self._publish(all_events)
        return _to_execution_dto(execution)

    async def record_task_completion(self, cmd: RecordTaskCompletionCommand) -> ExecutionDTO:
        now = datetime.now(UTC)
        tenant = TenantId(cmd.tenant_id)
        task_id = CampaignTaskId(cmd.task_id)

        try:
            outcome = TaskOutcome(cmd.outcome)
        except ValueError:
            raise ApplicationValidationError("outcome", f"Unknown outcome: {cmd.outcome}") from None

        async with self._uow_factory() as uow:
            execution = await uow.executions.find_by_id(
                TaskGraphExecutionId(cmd.execution_id), tenant
            )
            if execution is None:
                raise ApplicationNotFoundError("TaskGraphExecution", str(cmd.execution_id))

            monitor = await uow.safety_monitors.find_by_campaign_instance(
                CampaignInstanceId(execution.campaign_instance_ref.instance_id), tenant
            )

            if cmd.successors:
                ready_ids, skipped_ids = self._resolve_successors(
                    execution, outcome, task_id, cmd.successors
                )
            else:
                ready_ids = [CampaignTaskId(tid) for tid in cmd.ready_successor_ids]
                skipped_ids = [CampaignTaskId(tid) for tid in cmd.skipped_successor_ids]

            execution.record_task_completion(
                tenant,
                task_id,
                outcome,
                now,
                ready_successor_ids=ready_ids,
                skipped_successor_ids=skipped_ids,
            )

            if monitor is not None:
                monitor.release_action(tenant, str(task_id), now)

            await uow.executions.save(execution)
            if monitor is not None:
                await uow.safety_monitors.save(monitor)
            await uow.commit()

        all_events: list[BaseDomainEvent] = []
        all_events.extend(execution.pop_events())
        if monitor is not None:
            all_events.extend(monitor.pop_events())
        await self._publish(all_events)
        return _to_execution_dto(execution)

    async def resolve_conditional_branch(
        self, cmd: ResolveConditionalBranchCommand
    ) -> ExecutionDTO:
        now = datetime.now(UTC)
        tenant = TenantId(cmd.tenant_id)
        completed_id = CampaignTaskId(cmd.completed_task_id)
        try:
            outcome = TaskOutcome(cmd.outcome)
        except ValueError:
            raise ApplicationValidationError("outcome", f"Unknown outcome: {cmd.outcome}") from None

        async with self._uow_factory() as uow:
            execution = await uow.executions.find_by_id(
                TaskGraphExecutionId(cmd.execution_id), tenant
            )
            if execution is None:
                raise ApplicationNotFoundError("TaskGraphExecution", str(cmd.execution_id))

            ready_ids, skipped_ids = self._resolve_successors(
                execution, outcome, completed_id, cmd.successors
            )
            execution.record_task_completion(
                tenant,
                completed_id,
                outcome,
                now,
                ready_successor_ids=ready_ids,
                skipped_successor_ids=skipped_ids,
            )
            await uow.executions.save(execution)
            await uow.commit()

        await self._publish(execution.pop_events())
        return _to_execution_dto(execution)

    async def record_task_failure(self, cmd: RecordTaskFailureCommand) -> ExecutionDTO:
        now = datetime.now(UTC)
        tenant = TenantId(cmd.tenant_id)
        task_id = CampaignTaskId(cmd.task_id)

        async with self._uow_factory() as uow:
            execution = await uow.executions.find_by_id(
                TaskGraphExecutionId(cmd.execution_id), tenant
            )
            if execution is None:
                raise ApplicationNotFoundError("TaskGraphExecution", str(cmd.execution_id))

            monitor = await uow.safety_monitors.find_by_campaign_instance(
                CampaignInstanceId(execution.campaign_instance_ref.instance_id), tenant
            )

            execution.record_task_failure(tenant, task_id, cmd.failure_reason, now)
            if monitor is not None:
                monitor.release_action(tenant, str(task_id), now)

            await uow.executions.save(execution)
            if monitor is not None:
                await uow.safety_monitors.save(monitor)
            await uow.commit()

        all_events: list[BaseDomainEvent] = []
        all_events.extend(execution.pop_events())
        if monitor is not None:
            all_events.extend(monitor.pop_events())
        await self._publish(all_events)
        return _to_execution_dto(execution)

    async def evaluate_barrier(self, cmd: EvaluateBarrierCommand) -> ExecutionDTO:
        now = datetime.now(UTC)
        tenant = TenantId(cmd.tenant_id)
        barrier_id = CampaignTaskId(cmd.barrier_task_id)
        group_ids = [CampaignTaskId(tid) for tid in cmd.task_group_task_ids]

        async with self._uow_factory() as uow:
            execution = await uow.executions.find_by_id(
                TaskGraphExecutionId(cmd.execution_id), tenant
            )
            if execution is None:
                raise ApplicationNotFoundError("TaskGraphExecution", str(cmd.execution_id))

            execution.evaluate_barrier(tenant, barrier_id, group_ids, now)
            await uow.executions.save(execution)
            await uow.commit()

        await self._publish(execution.pop_events())
        return _to_execution_dto(execution)

    async def reach_human_approval_gate(self, cmd: ReachHumanApprovalGateCommand) -> ExecutionDTO:
        now = datetime.now(UTC)
        tenant = TenantId(cmd.tenant_id)
        pending_gate = PendingApprovalGate(
            task_id=CampaignTaskId(cmd.task_id),
            gate_created_at=now,
            gate_timeout_seconds=cmd.gate_timeout_seconds,
            required_approver_role=cmd.required_approver_role,
            default_on_timeout=cmd.default_on_timeout,
        )

        async with self._uow_factory() as uow:
            execution = await uow.executions.find_by_id(
                TaskGraphExecutionId(cmd.execution_id), tenant
            )
            if execution is None:
                raise ApplicationNotFoundError("TaskGraphExecution", str(cmd.execution_id))

            self._pause_coordinator.handle_human_approval_gate(execution, tenant, pending_gate, now)
            await uow.executions.save(execution)
            await uow.commit()

        await self._notification_port.notify_human_approval_gate(
            tenant_id=str(tenant),
            execution_id=str(execution.execution_id),
            task_id=str(cmd.task_id),
            required_approver_role=cmd.required_approver_role,
            gate_timeout_seconds=cmd.gate_timeout_seconds,
        )
        await self._publish(execution.pop_events())
        return _to_execution_dto(execution)

    async def grant_human_approval(self, cmd: GrantHumanApprovalCommand) -> ExecutionDTO:
        now = datetime.now(UTC)
        tenant = TenantId(cmd.tenant_id)

        async with self._uow_factory() as uow:
            execution = await uow.executions.find_by_id(
                TaskGraphExecutionId(cmd.execution_id), tenant
            )
            if execution is None:
                raise ApplicationNotFoundError("TaskGraphExecution", str(cmd.execution_id))

            execution.grant_human_approval(tenant, cmd.approver_id, now)
            await uow.executions.save(execution)
            await uow.commit()

        await self._publish(execution.pop_events())
        return _to_execution_dto(execution)

    async def deny_human_approval(self, cmd: DenyHumanApprovalCommand) -> ExecutionDTO:
        now = datetime.now(UTC)
        tenant = TenantId(cmd.tenant_id)

        async with self._uow_factory() as uow:
            execution = await uow.executions.find_by_id(
                TaskGraphExecutionId(cmd.execution_id), tenant
            )
            if execution is None:
                raise ApplicationNotFoundError("TaskGraphExecution", str(cmd.execution_id))

            execution.deny_human_approval(tenant, cmd.approver_id, cmd.reason, now)
            await uow.executions.save(execution)
            await uow.commit()

        await self._publish(execution.pop_events())
        return _to_execution_dto(execution)

    async def handle_approval_timeout(self, cmd: HandleApprovalTimeoutCommand) -> ExecutionDTO:
        now = datetime.now(UTC)
        tenant = TenantId(cmd.tenant_id)

        async with self._uow_factory() as uow:
            execution = await uow.executions.find_by_id(
                TaskGraphExecutionId(cmd.execution_id), tenant
            )
            if execution is None:
                raise ApplicationNotFoundError("TaskGraphExecution", str(cmd.execution_id))

            execution.handle_approval_timeout(tenant, now)
            await uow.executions.save(execution)
            await uow.commit()

        await self._publish(execution.pop_events())
        return _to_execution_dto(execution)

    async def pause_execution(self, cmd: PauseCampaignExecutionCommand) -> ExecutionDTO:
        now = datetime.now(UTC)
        tenant = TenantId(cmd.tenant_id)

        async with self._uow_factory() as uow:
            execution = await uow.executions.find_by_id(
                TaskGraphExecutionId(cmd.execution_id), tenant
            )
            if execution is None:
                raise ApplicationNotFoundError("TaskGraphExecution", str(cmd.execution_id))

            execution.pause(tenant, cmd.reason, now)
            await uow.executions.save(execution)
            await uow.commit()

        await self._notification_port.notify_campaign_paused(
            tenant_id=str(tenant),
            execution_id=str(execution.execution_id),
            reason=cmd.reason,
        )
        await self._publish(execution.pop_events())
        return _to_execution_dto(execution)

    async def resume_execution(self, cmd: ResumeCampaignExecutionCommand) -> ExecutionDTO:
        now = datetime.now(UTC)
        tenant = TenantId(cmd.tenant_id)

        async with self._uow_factory() as uow:
            execution = await uow.executions.find_by_id(
                TaskGraphExecutionId(cmd.execution_id), tenant
            )
            if execution is None:
                raise ApplicationNotFoundError("TaskGraphExecution", str(cmd.execution_id))

            execution.resume(tenant, now)
            await uow.executions.save(execution)
            await uow.commit()

        await self._publish(execution.pop_events())
        return _to_execution_dto(execution)

    async def handle_kill_switch_triggered(
        self, cmd: HandleKillSwitchTriggeredCommand
    ) -> ExecutionDTO:
        now = datetime.now(UTC)
        tenant = TenantId(cmd.tenant_id)

        async with self._uow_factory() as uow:
            execution = await uow.executions.find_by_id(
                TaskGraphExecutionId(cmd.execution_id), tenant
            )
            if execution is None:
                raise ApplicationNotFoundError("TaskGraphExecution", str(cmd.execution_id))

            self._pause_coordinator.handle_kill_switch_triggered(execution, tenant, now)
            await uow.executions.save(execution)
            await uow.commit()

        await self._notification_port.notify_campaign_paused(
            tenant_id=str(tenant),
            execution_id=str(execution.execution_id),
            reason="M29 kill switch triggered",
        )
        await self._publish(execution.pop_events())
        return _to_execution_dto(execution)

    async def initiate_rollback(self, cmd: InitiateRollbackCommand) -> ExecutionDTO:
        now = datetime.now(UTC)
        tenant = TenantId(cmd.tenant_id)
        eligible_ids = [CampaignTaskId(tid) for tid in cmd.rollback_eligible_task_ids]

        async with self._uow_factory() as uow:
            execution = await uow.executions.find_by_id(
                TaskGraphExecutionId(cmd.execution_id), tenant
            )
            if execution is None:
                raise ApplicationNotFoundError("TaskGraphExecution", str(cmd.execution_id))

            rollback_plan = self._rollback_executor.compute_rollback_plan(execution, eligible_ids)
            execution.initiate_rollback(tenant, cmd.trigger_reason, len(rollback_plan), now)

            rolled = 0
            for step in cmd.steps:
                await self._rollback_executor.execute_rollback_step(
                    execution=execution,
                    tenant_id=tenant,
                    task_id=CampaignTaskId(step.task_id),
                    rollback_technique_id=step.technique_id,
                    rollback_technique_name=step.technique_name,
                    rollback_parameters=dict(step.parameters),
                    port=self._operation_port,
                    now=now,
                )
                rolled += 1

            if cmd.steps and rolled == len(cmd.steps):
                execution.complete_rollback(tenant, rolled, now)

            await uow.executions.save(execution)
            await uow.commit()

        await self._publish(execution.pop_events())
        return _to_execution_dto(execution)

    async def complete_execution(self, cmd: CompleteExecutionCommand) -> ExecutionDTO:
        now = datetime.now(UTC)
        tenant = TenantId(cmd.tenant_id)

        async with self._uow_factory() as uow:
            execution = await uow.executions.find_by_id(
                TaskGraphExecutionId(cmd.execution_id), tenant
            )
            if execution is None:
                raise ApplicationNotFoundError("TaskGraphExecution", str(cmd.execution_id))

            monitor = await uow.safety_monitors.find_by_campaign_instance(
                CampaignInstanceId(execution.campaign_instance_ref.instance_id), tenant
            )

            execution.complete(tenant, now)
            if monitor is not None:
                monitor.release(tenant, now)

            await uow.executions.save(execution)
            if monitor is not None:
                await uow.safety_monitors.save(monitor)
            await uow.commit()

        all_events: list[BaseDomainEvent] = []
        all_events.extend(execution.pop_events())
        if monitor is not None:
            all_events.extend(monitor.pop_events())
        await self._publish(all_events)
        return _to_execution_dto(execution)

    async def abort_execution(self, cmd: AbortExecutionCommand) -> ExecutionDTO:
        now = datetime.now(UTC)
        tenant = TenantId(cmd.tenant_id)

        async with self._uow_factory() as uow:
            execution = await uow.executions.find_by_id(
                TaskGraphExecutionId(cmd.execution_id), tenant
            )
            if execution is None:
                raise ApplicationNotFoundError("TaskGraphExecution", str(cmd.execution_id))

            monitor = await uow.safety_monitors.find_by_campaign_instance(
                CampaignInstanceId(execution.campaign_instance_ref.instance_id), tenant
            )

            execution.abort(tenant, cmd.abort_reason, now)
            if monitor is not None:
                monitor.release(tenant, now)

            await uow.executions.save(execution)
            if monitor is not None:
                await uow.safety_monitors.save(monitor)
            await uow.commit()

        all_events: list[BaseDomainEvent] = []
        all_events.extend(execution.pop_events())
        if monitor is not None:
            all_events.extend(monitor.pop_events())
        await self._publish(all_events)
        return _to_execution_dto(execution)

    async def trigger_auto_abort_on_detection(
        self, cmd: TriggerAutoAbortOnDetectionCommand
    ) -> SafetyMonitorDTO | None:
        now = datetime.now(UTC)
        tenant = TenantId(cmd.tenant_id)
        instance_id = CampaignInstanceId(cmd.campaign_instance_id)

        async with self._uow_factory() as uow:
            monitor = await uow.safety_monitors.find_by_campaign_instance(instance_id, tenant)
            if monitor is None:
                return None

            monitor.trigger_auto_abort_on_detection(tenant, cmd.detection_detail, now)
            execution = await uow.executions.find_by_campaign_instance(instance_id, tenant)
            if execution is not None:
                self._pause_coordinator.handle_safety_breach(
                    execution,
                    tenant,
                    breach_type="AutoAbortOnDetection",
                    details=cmd.detection_detail,
                    now=now,
                )
                await uow.executions.save(execution)

            await uow.safety_monitors.save(monitor)
            await uow.commit()

        events: list[BaseDomainEvent] = list(monitor.pop_events())
        if execution is not None:
            events.extend(execution.pop_events())
            await self._notification_port.notify_campaign_paused(
                tenant_id=str(tenant),
                execution_id=str(execution.execution_id),
                reason=f"Auto-abort on detection: {cmd.detection_detail}",
            )
        await self._publish(events)
        return _to_monitor_dto(monitor)

    async def get_execution(self, query: GetExecutionQuery) -> ExecutionDTO | None:
        tenant = TenantId(query.tenant_id)
        async with self._uow_factory() as uow:
            execution = await uow.executions.find_by_id(
                TaskGraphExecutionId(query.execution_id), tenant
            )
            if execution is None:
                return None
            return _to_execution_dto(execution)
