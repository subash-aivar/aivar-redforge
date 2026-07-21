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
    """Coordinates runtime rollback within the campaignexecution context.

    Ordering uses reverse completion order of eligible completed tasks
    (same algorithm as taskgraph RollbackPlanComputer, owned locally to avoid
    bounded-context leakage). Each rollback step is dispatched as an M29
    operation via the ACL port.
    """

    def compute_rollback_plan(
        self,
        execution: TaskGraphExecution,
        rollback_eligible_task_ids: list[CampaignTaskId],
    ) -> list[TaskExecutionRecord]:
        """Return completed eligible tasks in reverse completion order."""
        from campaignexecution.domain.value_objects.enums import TaskExecutionState

        eligible_ids = {tid.value for tid in rollback_eligible_task_ids}
        completed_ordered = [
            rec
            for rec in sorted(
                (r for r in execution.task_records if r.state == TaskExecutionState.COMPLETED),
                key=lambda r: r.completed_at or r.dispatched_at or r.task_id.value,
            )
        ]
        ordered_ids = [
            rec.task_id.value
            for rec in reversed(completed_ordered)
            if rec.task_id.value in eligible_ids
        ]
        by_id = {rec.task_id.value: rec for rec in completed_ordered}
        return [by_id[tid] for tid in ordered_ids if tid in by_id]

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
