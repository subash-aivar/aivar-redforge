"""RollbackExecutor — coordinates rollback of completed tasks in reverse order."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from campaignexecution.domain.aggregates.task_graph_execution import TaskGraphExecution
    from campaignexecution.domain.entities.execution_entities import TaskExecutionRecord
    from campaignexecution.domain.ports.i_operation_creation_port import IOperationCreationPort
    from campaignexecution.domain.value_objects.identifiers import CampaignTaskId, TenantId


class RollbackExecutor:
    """Coordinates rollback using reverse topological order from taskgraph context.

    Only tasks with is_rollback_task=True participate in rollback.
    Each rollback step is dispatched as an M29 operation via the port.
    """

    def compute_rollback_plan(
        self,
        execution: TaskGraphExecution,
        rollback_eligible_task_ids: list[CampaignTaskId],
    ) -> list[TaskExecutionRecord]:
        """Return completed tasks that have rollback configs, in reverse completion order."""
        from campaignexecution.domain.value_objects.enums import TaskExecutionState

        eligible_ids = frozenset(rollback_eligible_task_ids)
        completed_with_rollback = [
            rec
            for rec in execution.task_records
            if rec.state == TaskExecutionState.COMPLETED
            and rec.task_id in eligible_ids
        ]
        # Sort by completion time (most recently completed first — rollback in reverse order)
        fallback = execution.campaign_instance_ref.instance_id
        completed_with_rollback.sort(
            key=lambda r: r.completed_at or r.dispatched_at or fallback,
            reverse=True,
        )
        return completed_with_rollback

    async def execute_rollback_step(
        self,
        execution: TaskGraphExecution,
        tenant_id: TenantId,
        task_id: CampaignTaskId,
        rollback_technique_id: str,
        rollback_technique_name: str,
        rollback_parameters: dict[str, str],
        port: IOperationCreationPort,
        now: datetime,
    ) -> None:
        """Dispatch a single rollback step to M29 and record the result."""
        from campaignexecution.domain.services.task_dispatch_service import TaskDispatchService
        from campaignexecution.domain.value_objects.identifiers import CampaignInstanceId

        dispatch_svc = TaskDispatchService()
        instance_ref = execution.campaign_instance_ref
        operation_ref = await dispatch_svc.dispatch(
            tenant_id=tenant_id,
            campaign_instance_id=CampaignInstanceId(instance_ref.instance_id),
            task_id=task_id,
            technique_id=rollback_technique_id,
            technique_name=rollback_technique_name,
            parameters={**rollback_parameters, "_rollback": "true"},
            engagement_ref=execution.engagement_ref,
            port=port,
        )
        execution.record_task_rolled_back(tenant_id, task_id, operation_ref, now)
