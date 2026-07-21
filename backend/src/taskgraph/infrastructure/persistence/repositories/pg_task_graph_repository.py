"""PgTaskGraphRepository — SQLAlchemy implementation with optimistic locking."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import uuid7

from sqlalchemy import select, update

from taskgraph.domain.aggregates.task_graph import TaskGraph
from taskgraph.domain.entities.task_graph_entities import CampaignTask, TaskDependency
from taskgraph.domain.exceptions.domain_exceptions import OptimisticLockConflict
from taskgraph.domain.repositories.i_task_graph_repository import ITaskGraphRepository
from taskgraph.domain.value_objects.enums import (
    DependencyPredicate,
    TaskCriticality,
    TaskGraphState,
    TaskType,
)
from taskgraph.domain.value_objects.identifiers import (
    CampaignTaskId,
    TaskGraphId,
    TaskGroupId,
    TenantId,
)
from taskgraph.domain.value_objects.task_graph_vos import (
    BarrierPolicy,
    ConditionalBranchConfig,
    HumanApprovalTaskConfig,
    RollbackConfiguration,
    TaskGraphVersion,
    TaskOperationTemplate,
)
from taskgraph.infrastructure.persistence.models.task_graph_models import (
    CampaignTaskModel,
    TaskDependencyModel,
    TaskGraphModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


# ---------------------------------------------------------------------------
# JSON serialization helpers
# ---------------------------------------------------------------------------


def _operation_template_to_json(
    tmpl: TaskOperationTemplate | None,
) -> dict[str, Any] | None:
    if tmpl is None:
        return None
    return {
        "technique_id": tmpl.technique_id,
        "technique_name": tmpl.technique_name,
        "parameters": dict(tmpl.parameters),
        "timeout_seconds": tmpl.timeout_seconds,
    }


def _operation_template_from_json(
    data: dict[str, Any] | None,
) -> TaskOperationTemplate | None:
    if data is None:
        return None
    return TaskOperationTemplate(
        technique_id=str(data["technique_id"]),
        technique_name=str(data.get("technique_name", "")),
        parameters=dict(data.get("parameters") or {}),
        timeout_seconds=int(data["timeout_seconds"]),
    )


def _human_approval_to_json(
    cfg: HumanApprovalTaskConfig | None,
) -> dict[str, Any] | None:
    if cfg is None:
        return None
    return {
        "gate_timeout_seconds": cfg.gate_timeout_seconds,
        "required_approver_role": cfg.required_approver_role,
        "default_on_timeout": cfg.default_on_timeout,
        "timeout_justification": cfg.timeout_justification,
    }


def _human_approval_from_json(
    data: dict[str, Any] | None,
) -> HumanApprovalTaskConfig | None:
    if data is None:
        return None
    return HumanApprovalTaskConfig(
        gate_timeout_seconds=int(data["gate_timeout_seconds"]),
        required_approver_role=str(data["required_approver_role"]),
        default_on_timeout=str(data.get("default_on_timeout", "abort")),
        timeout_justification=data.get("timeout_justification"),
    )


def _barrier_policy_to_json(
    policy: BarrierPolicy | None,
) -> dict[str, Any] | None:
    if policy is None:
        return None
    return {"task_group_id": policy.task_group_id}


def _barrier_policy_from_json(
    data: dict[str, Any] | None,
) -> BarrierPolicy | None:
    if data is None:
        return None
    return BarrierPolicy(task_group_id=str(data["task_group_id"]))


def _rollback_config_to_json(
    cfg: RollbackConfiguration | None,
) -> dict[str, Any] | None:
    if cfg is None:
        return None
    return {
        "rollback_technique_id": cfg.rollback_technique_id,
        "rollback_parameters": dict(cfg.rollback_parameters),
        "rollback_not_possible": cfg.rollback_not_possible,
        "rollback_not_possible_reason": cfg.rollback_not_possible_reason,
    }


def _rollback_config_from_json(
    data: dict[str, Any] | None,
) -> RollbackConfiguration | None:
    if data is None:
        return None
    return RollbackConfiguration(
        rollback_technique_id=str(data["rollback_technique_id"]),
        rollback_parameters=dict(data.get("rollback_parameters") or {}),
        rollback_not_possible=bool(data.get("rollback_not_possible", False)),
        rollback_not_possible_reason=data.get("rollback_not_possible_reason"),
    )


# ---------------------------------------------------------------------------
# Domain reconstruction
# ---------------------------------------------------------------------------


def _to_domain(row: TaskGraphModel) -> TaskGraph:
    tasks = [
        CampaignTask(
            task_id=CampaignTaskId(t.id),
            task_type=TaskType(t.task_type),
            name=t.name,
            criticality=TaskCriticality(t.criticality),
            timeout_seconds=t.timeout_seconds,
            operation_template=_operation_template_from_json(t.operation_template_json),
            human_approval_config=_human_approval_from_json(t.human_approval_config_json),
            barrier_policy=_barrier_policy_from_json(t.barrier_policy_json),
            rollback_config=_rollback_config_from_json(t.rollback_config_json),
            task_group_id=TaskGroupId(t.task_group_id) if t.task_group_id else None,
            rollback_task_ref=(
                CampaignTaskId(t.rollback_task_ref_id) if t.rollback_task_ref_id else None
            ),
        )
        for t in row.tasks
    ]
    dependencies = [
        TaskDependency(
            predecessor_id=CampaignTaskId(d.predecessor_id),
            successor_id=CampaignTaskId(d.successor_id),
            condition=ConditionalBranchConfig(
                predicate=DependencyPredicate(d.predicate),
                objective_ref=d.objective_ref,
            ),
        )
        for d in row.dependencies
    ]
    return TaskGraph(
        graph_id=TaskGraphId(row.id),
        tenant_id=TenantId(row.tenant_id),
        name=row.name,
        description=row.description,
        state=TaskGraphState(row.state),
        version=TaskGraphVersion(
            major=row.version_major,
            minor=row.version_minor,
            patch=row.version_patch,
        ),
        tasks=tasks,
        dependencies=dependencies,
        engagement_window_seconds=row.engagement_window_seconds,
        signed_by=row.signed_by,
        signed_at=row.signed_at,
        signature=row.signature,
        created_at=row.created_at,
        updated_at=row.updated_at,
        row_version=row.row_version,
    )


class PgTaskGraphRepository(ITaskGraphRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, graph: TaskGraph) -> None:
        stmt = select(TaskGraphModel).where(
            TaskGraphModel.id == graph.graph_id.value,
            TaskGraphModel.tenant_id == graph.tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()

        if row is None:
            row = TaskGraphModel(
                id=graph.graph_id.value,
                tenant_id=graph.tenant_id.value,
                name=graph.name,
                description=graph.description,
                state=graph.state.value,
                version_major=graph.version.major,
                version_minor=graph.version.minor,
                version_patch=graph.version.patch,
                engagement_window_seconds=graph.engagement_window_seconds,
                signed_by=graph.signed_by,
                signed_at=graph.signed_at,
                signature=graph.signature,
                created_at=graph.created_at,
                updated_at=graph.updated_at,
                row_version=graph.row_version,
            )
            self._session.add(row)
            await self._session.flush()
            await self._sync_children(row, graph)
            return

        # Optimistic locking: domain _mutate increments _version to N+1; stored is N.
        expected = graph.row_version - 1
        if expected < 1:
            expected = 1

        upd = (
            update(TaskGraphModel)
            .where(
                TaskGraphModel.id == graph.graph_id.value,
                TaskGraphModel.tenant_id == graph.tenant_id.value,
                TaskGraphModel.row_version == expected,
            )
            .values(
                name=graph.name,
                description=graph.description,
                state=graph.state.value,
                version_major=graph.version.major,
                version_minor=graph.version.minor,
                version_patch=graph.version.patch,
                engagement_window_seconds=graph.engagement_window_seconds,
                signed_by=graph.signed_by,
                signed_at=graph.signed_at,
                signature=graph.signature,
                updated_at=graph.updated_at,
                row_version=graph.row_version,
            )
            .returning(TaskGraphModel.row_version)
        )
        upd_result = await self._session.execute(upd)
        new_version = upd_result.scalar_one_or_none()
        if new_version is None:
            actual_stmt = select(TaskGraphModel.row_version).where(
                TaskGraphModel.id == graph.graph_id.value,
                TaskGraphModel.tenant_id == graph.tenant_id.value,
            )
            actual = (await self._session.execute(actual_stmt)).scalar_one_or_none() or 0
            raise OptimisticLockConflict(
                str(graph.graph_id),
                expected,
                int(actual),
            )

        await self._session.refresh(row)
        await self._sync_children(row, graph)

    async def _sync_children(self, row: TaskGraphModel, graph: TaskGraph) -> None:
        row.tasks.clear()
        row.dependencies.clear()
        await self._session.flush()

        for task in graph.tasks:
            row.tasks.append(
                CampaignTaskModel(
                    id=task.task_id.value,
                    graph_id=graph.graph_id.value,
                    tenant_id=graph.tenant_id.value,
                    task_type=task.task_type.value,
                    name=task.name,
                    criticality=task.criticality.value,
                    timeout_seconds=task.timeout_seconds,
                    operation_template_json=_operation_template_to_json(task.operation_template),
                    human_approval_config_json=_human_approval_to_json(task.human_approval_config),
                    barrier_policy_json=_barrier_policy_to_json(task.barrier_policy),
                    rollback_config_json=_rollback_config_to_json(task.rollback_config),
                    task_group_id=(str(task.task_group_id) if task.task_group_id else None),
                    rollback_task_ref_id=(
                        task.rollback_task_ref.value if task.rollback_task_ref else None
                    ),
                )
            )

        for dep in graph.dependencies:
            row.dependencies.append(
                TaskDependencyModel(
                    id=uuid7(),
                    graph_id=graph.graph_id.value,
                    predecessor_id=dep.predecessor_id.value,
                    successor_id=dep.successor_id.value,
                    predicate=dep.condition.predicate.value,
                    objective_ref=dep.condition.objective_ref,
                )
            )
        await self._session.flush()

    async def find_by_id(
        self,
        graph_id: TaskGraphId,
        tenant_id: TenantId,
    ) -> TaskGraph | None:
        stmt = select(TaskGraphModel).where(
            TaskGraphModel.id == graph_id.value,
            TaskGraphModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        return _to_domain(row) if row is not None else None

    async def find_signed_version(
        self,
        graph_id: TaskGraphId,
        version: TaskGraphVersion,
        tenant_id: TenantId,
    ) -> TaskGraph | None:
        stmt = select(TaskGraphModel).where(
            TaskGraphModel.id == graph_id.value,
            TaskGraphModel.tenant_id == tenant_id.value,
            TaskGraphModel.version_major == version.major,
            TaskGraphModel.version_minor == version.minor,
            TaskGraphModel.version_patch == version.patch,
            TaskGraphModel.state.in_(
                [
                    TaskGraphState.SIGNED.value,
                    TaskGraphState.ACTIVE.value,
                    TaskGraphState.DEPRECATED.value,
                ]
            ),
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        return _to_domain(row) if row is not None else None

    async def find_active_by_tenant(self, tenant_id: TenantId) -> list[TaskGraph]:
        stmt = select(TaskGraphModel).where(
            TaskGraphModel.tenant_id == tenant_id.value,
            TaskGraphModel.state == TaskGraphState.ACTIVE.value,
        )
        result = await self._session.execute(stmt)
        return [_to_domain(row) for row in result.scalars().all()]
