"""PostgreSQL repository for TaskGraphExecution aggregate."""

from __future__ import annotations

from datetime import UTC
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import select, update

from campaignexecution.domain.aggregates.task_graph_execution import TaskGraphExecution
from campaignexecution.domain.entities.execution_entities import (
    TaskExecutionRecord,
)
from campaignexecution.domain.exceptions.domain_exceptions import ConcurrencyConflict
from campaignexecution.domain.repositories.i_task_graph_execution_repository import (
    ITaskGraphExecutionRepository,
)
from campaignexecution.domain.value_objects.enums import (
    ExecutionState,
    TaskExecutionState,
    TaskOutcome,
)
from campaignexecution.domain.value_objects.execution_vos import (
    CampaignInstanceRef,
    EngagementRef,
    ObjectiveStateMap,
    OperationRef,
    PolicySnapshot,
    TaskGraphVersionRef,
)
from campaignexecution.domain.value_objects.identifiers import (
    CampaignInstanceId,
    CampaignTaskId,
    TaskExecutionRecordId,
    TaskGraphExecutionId,
    TenantId,
)
from campaignexecution.infrastructure.persistence.models.execution_models import (
    TaskExecutionRecordModel,
    TaskGraphExecutionModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _policy_from_json(data: dict[str, Any]) -> PolicySnapshot:
    return PolicySnapshot(
        max_concurrent_actions=data.get("max_concurrent_actions", 10),
        auto_abort_on_detection=data.get("auto_abort_on_detection", False),
        auto_abort_on_objective_failure=data.get("auto_abort_on_objective_failure", False),
        blast_radius_ceiling=data.get("blast_radius_ceiling", "Medium"),
    )


def _policy_to_json(p: PolicySnapshot) -> dict[str, Any]:
    return {
        "max_concurrent_actions": p.max_concurrent_actions,
        "auto_abort_on_detection": p.auto_abort_on_detection,
        "auto_abort_on_objective_failure": p.auto_abort_on_objective_failure,
        "blast_radius_ceiling": p.blast_radius_ceiling,
    }


def _record_from_model(m: TaskExecutionRecordModel) -> TaskExecutionRecord:
    operation_ref = None
    if m.operation_id is not None and m.operation_tenant_id is not None:
        operation_ref = OperationRef(
            operation_id=m.operation_id,
            tenant_id=m.operation_tenant_id,
        )
    return TaskExecutionRecord(
        record_id=TaskExecutionRecordId(m.id),
        task_id=CampaignTaskId(m.task_id),
        state=TaskExecutionState(m.state),
        outcome=TaskOutcome(m.outcome) if m.outcome else None,
        operation_ref=operation_ref,
        dispatched_at=m.dispatched_at,
        completed_at=m.completed_at,
        failure_reason=m.failure_reason,
        is_rollback_task=m.is_rollback_task,
    )


def _execution_from_row(
    row: TaskGraphExecutionModel,
    records: list[TaskExecutionRecord],
) -> TaskGraphExecution:
    from campaignexecution.domain.value_objects.execution_vos import PendingApprovalGate

    pending_gate = None
    if row.pending_approval_gate_json:
        from datetime import datetime

        gate_data = row.pending_approval_gate_json
        pending_gate = PendingApprovalGate(
            task_id=CampaignTaskId(UUID(gate_data["task_id"])),
            gate_created_at=datetime.fromisoformat(gate_data["gate_created_at"]).replace(
                tzinfo=UTC
            ),
            gate_timeout_seconds=gate_data["gate_timeout_seconds"],
            required_approver_role=gate_data["required_approver_role"],
            default_on_timeout=gate_data["default_on_timeout"],
        )

    obj_states = ObjectiveStateMap(states=dict(row.objective_states_json or {}))

    return TaskGraphExecution(
        execution_id=TaskGraphExecutionId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        campaign_instance_ref=CampaignInstanceRef(
            instance_id=row.campaign_instance_id,
            campaign_id=row.campaign_id,
            tenant_id=row.tenant_id,
        ),
        graph_version_ref=TaskGraphVersionRef(
            graph_id=row.graph_id,
            version_str=row.graph_version,
        ),
        engagement_ref=EngagementRef(
            engagement_id=row.engagement_id,
            tenant_id=row.tenant_id,
        ),
        policy_snapshot=_policy_from_json(row.policy_snapshot_json),
        state=ExecutionState(row.state),
        task_records=records,
        tracks=[],
        checkpoints=[],
        objective_states=obj_states,
        pending_approval_gate=pending_gate,
        version=row.row_version,
    )


class PgTaskGraphExecutionRepository(ITaskGraphExecutionRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, execution: TaskGraphExecution) -> None:
        pending_gate_json = None
        if execution.pending_approval_gate:
            gate = execution.pending_approval_gate
            pending_gate_json = {
                "task_id": str(gate.task_id),
                "gate_created_at": gate.gate_created_at.isoformat(),
                "gate_timeout_seconds": gate.gate_timeout_seconds,
                "required_approver_role": gate.required_approver_role,
                "default_on_timeout": gate.default_on_timeout,
            }

        stmt = select(TaskGraphExecutionModel).where(
            TaskGraphExecutionModel.id == execution.execution_id.value,
            TaskGraphExecutionModel.tenant_id == execution.tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()

        if row is None:
            row = TaskGraphExecutionModel(
                id=execution.execution_id.value,
                tenant_id=execution.tenant_id.value,
                campaign_instance_id=execution.campaign_instance_ref.instance_id,
                campaign_id=execution.campaign_instance_ref.campaign_id,
                engagement_id=execution.engagement_ref.engagement_id,
                graph_id=execution.graph_version_ref.graph_id,
                graph_version=execution.graph_version_ref.version_str,
                state=execution.state.value,
                policy_snapshot_json=_policy_to_json(execution.policy_snapshot),
                pending_approval_gate_json=pending_gate_json,
                objective_states_json=dict(execution.objective_states.states),
                row_version=execution.version,
            )
            self._session.add(row)
            await self._session.flush()
            await self._sync_records(row, execution)
            return

        expected = max(execution.version - 1, 1)
        upd = (
            update(TaskGraphExecutionModel)
            .where(
                TaskGraphExecutionModel.id == execution.execution_id.value,
                TaskGraphExecutionModel.tenant_id == execution.tenant_id.value,
                TaskGraphExecutionModel.row_version == expected,
            )
            .values(
                state=execution.state.value,
                pending_approval_gate_json=pending_gate_json,
                objective_states_json=dict(execution.objective_states.states),
                row_version=execution.version,
            )
            .returning(TaskGraphExecutionModel.row_version)
        )
        result2 = await self._session.execute(upd)
        if result2.scalar_one_or_none() is None:
            raise ConcurrencyConflict(str(execution.execution_id))
        await self._session.flush()
        await self._sync_records(row, execution)

    async def _sync_records(
        self,
        row: TaskGraphExecutionModel,
        execution: TaskGraphExecution,
    ) -> None:
        for rec in execution.task_records:
            op_id = rec.operation_ref.operation_id if rec.operation_ref else None
            op_tid = rec.operation_ref.tenant_id if rec.operation_ref else None

            rec_stmt = select(TaskExecutionRecordModel).where(
                TaskExecutionRecordModel.id == rec.record_id.value,
            )
            rec_result = await self._session.execute(rec_stmt)
            rec_row = rec_result.scalar_one_or_none()

            if rec_row is None:
                rec_row = TaskExecutionRecordModel(
                    id=rec.record_id.value,
                    execution_id=execution.execution_id.value,
                    task_id=rec.task_id.value,
                    state=rec.state.value,
                    outcome=rec.outcome.value if rec.outcome else None,
                    operation_id=op_id,
                    operation_tenant_id=op_tid,
                    dispatched_at=rec.dispatched_at,
                    completed_at=rec.completed_at,
                    failure_reason=rec.failure_reason,
                    is_rollback_task=rec.is_rollback_task,
                )
                self._session.add(rec_row)
            else:
                rec_row.state = rec.state.value
                rec_row.outcome = rec.outcome.value if rec.outcome else None
                rec_row.operation_id = op_id
                rec_row.operation_tenant_id = op_tid
                rec_row.dispatched_at = rec.dispatched_at
                rec_row.completed_at = rec.completed_at
                rec_row.failure_reason = rec.failure_reason
        await self._session.flush()

    async def find_by_id(
        self,
        execution_id: TaskGraphExecutionId,
        tenant_id: TenantId,
    ) -> TaskGraphExecution | None:
        stmt = select(TaskGraphExecutionModel).where(
            TaskGraphExecutionModel.id == execution_id.value,
            TaskGraphExecutionModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        records = [_record_from_model(m) for m in row.task_records]
        return _execution_from_row(row, records)

    async def find_by_campaign_instance(
        self,
        instance_id: CampaignInstanceId,
        tenant_id: TenantId,
    ) -> TaskGraphExecution | None:
        stmt = select(TaskGraphExecutionModel).where(
            TaskGraphExecutionModel.campaign_instance_id == instance_id.value,
            TaskGraphExecutionModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        records = [_record_from_model(m) for m in row.task_records]
        return _execution_from_row(row, records)

    async def find_pending_dispatch_by_tenant(
        self,
        tenant_id: TenantId,
    ) -> list[TaskExecutionRecord]:
        stmt = (
            select(TaskExecutionRecordModel)
            .join(
                TaskGraphExecutionModel,
                TaskExecutionRecordModel.execution_id == TaskGraphExecutionModel.id,
            )
            .where(
                TaskGraphExecutionModel.tenant_id == tenant_id.value,
                TaskExecutionRecordModel.state == TaskExecutionState.READY_TO_DISPATCH.value,
            )
        )
        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        return [_record_from_model(m) for m in rows]
