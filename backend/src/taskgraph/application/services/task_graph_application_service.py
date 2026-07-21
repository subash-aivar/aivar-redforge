"""TaskGraphApplicationService — validate → UoW → domain → save → commit → publish."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from taskgraph.application._validation import validate_str, validate_uuid
from taskgraph.application.dtos.task_graph_dtos import (
    ExecutionOrderDTO,
    TaskDTO,
    TaskGraphDTO,
    ValidationResultDTO,
)
from taskgraph.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from taskgraph.domain.aggregates.task_graph import TaskGraph
from taskgraph.domain.entities.task_graph_entities import CampaignTask
from taskgraph.domain.exceptions.domain_exceptions import TaskGraphValidationFailed
from taskgraph.domain.services.execution_order_resolver import ExecutionOrderResolver
from taskgraph.domain.services.task_graph_validator import TaskGraphValidator
from taskgraph.domain.value_objects.enums import (
    DependencyPredicate,
    TaskCriticality,
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
    TaskOperationTemplate,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from taskgraph.application.commands.task_graph_commands import (
        ActivateTaskGraphCommand,
        AddDependencyCommand,
        AddTaskCommand,
        CreateTaskGraphCommand,
        DeprecateTaskGraphCommand,
        GetExecutionOrderQuery,
        GetTaskGraphQuery,
        SignTaskGraphCommand,
        ValidateTaskGraphCommand,
    )
    from taskgraph.application.ports.i_event_publisher import IEventPublisher
    from taskgraph.application.ports.i_unit_of_work import IUnitOfWork
    from taskgraph.domain.events.base import BaseDomainEvent

logger = logging.getLogger(__name__)


def _as_uuid(field: str, value: object) -> UUID:
    if isinstance(value, UUID):
        validate_uuid(value, field)
        return value
    try:
        parsed = UUID(str(value))
    except (TypeError, ValueError) as exc:
        raise ApplicationValidationError(field, f"invalid UUID: {value}") from exc
    validate_uuid(parsed, field)
    return parsed


def _as_str(field: str, value: str, max_len: int = 512) -> str:
    validate_str(value, field, max_len)
    return value.strip()


def _now() -> datetime:
    return datetime.now(UTC)


def graph_to_dto(graph: TaskGraph) -> TaskGraphDTO:
    return TaskGraphDTO(
        graph_id=graph.graph_id.value,
        tenant_id=graph.tenant_id.value,
        name=graph.name,
        description=graph.description,
        state=graph.state.value,
        version_str=str(graph.version),
        task_count=len(graph.tasks),
        dependency_count=len(graph.dependencies),
        engagement_window_seconds=graph.engagement_window_seconds,
        signed_by=graph.signed_by,
        signed_at=graph.signed_at,
        created_at=graph.created_at,
        updated_at=graph.updated_at,
    )


def task_to_dto(task: CampaignTask) -> TaskDTO:
    return TaskDTO(
        task_id=task.task_id.value,
        task_type=task.task_type.value,
        name=task.name,
        criticality=task.criticality.value,
        timeout_seconds=task.timeout_seconds,
        task_group_id=str(task.task_group_id) if task.task_group_id else None,
    )


class TaskGraphApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher
        self._validator = TaskGraphValidator()
        self._resolver = ExecutionOrderResolver()

    async def _publish_all(self, *aggregates: object) -> None:
        events: list[BaseDomainEvent] = []
        for agg in aggregates:
            pop = getattr(agg, "pop_events", None)
            if callable(pop):
                events.extend(pop())
        if not events:
            return
        try:
            await self._event_publisher.publish_batch(events)
        except Exception as exc:
            logger.warning("Event publication failed: %s", exc)

    def _tenant(self, value: UUID) -> TenantId:
        return TenantId(_as_uuid("tenant_id", value))

    async def _load_graph(
        self,
        uow: IUnitOfWork,
        graph_id: UUID,
        tenant: TenantId,
    ) -> TaskGraph:
        gid = TaskGraphId(_as_uuid("graph_id", graph_id))
        graph = await uow.task_graphs.find_by_id(gid, tenant)
        if graph is None:
            raise ApplicationNotFoundError("TaskGraph", str(gid))
        return graph

    async def create_task_graph(
        self, cmd: CreateTaskGraphCommand
    ) -> TaskGraphDTO:
        tenant = self._tenant(cmd.tenant_id)
        name = _as_str("name", cmd.name)
        if cmd.engagement_window_seconds <= 0:
            raise ApplicationValidationError(
                "engagement_window_seconds", "must be positive"
            )
        now = _now()
        graph = TaskGraph.create(
            graph_id=TaskGraphId.generate(),
            tenant_id=tenant,
            name=name,
            description=cmd.description.strip(),
            engagement_window_seconds=cmd.engagement_window_seconds,
            now=now,
        )
        async with self._uow_factory() as uow:
            await uow.task_graphs.save(graph)
            await uow.commit()
        await self._publish_all(graph)
        return graph_to_dto(graph)

    async def add_task(self, cmd: AddTaskCommand) -> TaskDTO:
        tenant = self._tenant(cmd.tenant_id)
        try:
            task_type = TaskType(cmd.task_type)
        except ValueError as exc:
            raise ApplicationValidationError("task_type", f"invalid: {cmd.task_type}") from exc
        try:
            criticality = TaskCriticality(cmd.criticality)
        except ValueError as exc:
            raise ApplicationValidationError(
                "criticality", f"invalid: {cmd.criticality}"
            ) from exc

        if cmd.timeout_seconds <= 0:
            raise ApplicationValidationError("timeout_seconds", "must be positive")

        operation_template: TaskOperationTemplate | None = None
        if task_type == TaskType.OPERATION_TASK:
            if not cmd.technique_id:
                raise ApplicationValidationError(
                    "technique_id", "required for OperationTask"
                )
            operation_template = TaskOperationTemplate(
                technique_id=cmd.technique_id,
                technique_name=cmd.technique_name or "",
                parameters=dict(cmd.technique_parameters or {}),
                timeout_seconds=cmd.timeout_seconds,
            )

        human_approval_config: HumanApprovalTaskConfig | None = None
        if task_type == TaskType.HUMAN_APPROVAL_TASK:
            if cmd.human_approval_timeout_seconds is None:
                raise ApplicationValidationError(
                    "human_approval_timeout_seconds", "required for HumanApprovalTask"
                )
            if not cmd.human_approval_required_role:
                raise ApplicationValidationError(
                    "human_approval_required_role", "required for HumanApprovalTask"
                )
            default_on_timeout = cmd.human_approval_default_on_timeout or "abort"
            human_approval_config = HumanApprovalTaskConfig(
                gate_timeout_seconds=cmd.human_approval_timeout_seconds,
                required_approver_role=cmd.human_approval_required_role,
                default_on_timeout=default_on_timeout,
                timeout_justification=cmd.human_approval_timeout_justification,
            )

        barrier_policy: BarrierPolicy | None = None
        if task_type == TaskType.BARRIER_TASK:
            if not cmd.barrier_task_group_id:
                raise ApplicationValidationError(
                    "barrier_task_group_id", "required for BarrierTask"
                )
            barrier_policy = BarrierPolicy(task_group_id=cmd.barrier_task_group_id)

        rollback_task_ref: CampaignTaskId | None = None
        rollback_config: RollbackConfiguration | None = None
        if task_type == TaskType.ROLLBACK_TASK:
            if cmd.rollback_task_ref_id is None:
                raise ApplicationValidationError(
                    "rollback_task_ref_id", "required for RollbackTask"
                )
            rollback_task_ref = CampaignTaskId(
                _as_uuid("rollback_task_ref_id", cmd.rollback_task_ref_id)
            )

        if cmd.rollback_technique_id:
            rollback_config = RollbackConfiguration(
                rollback_technique_id=cmd.rollback_technique_id,
                rollback_parameters={},
                rollback_not_possible=cmd.rollback_not_possible,
                rollback_not_possible_reason=cmd.rollback_not_possible_reason,
            )

        task_group_id: TaskGroupId | None = None
        if cmd.task_group_id:
            task_group_id = TaskGroupId(cmd.task_group_id)

        task = CampaignTask(
            task_id=CampaignTaskId.generate(),
            task_type=task_type,
            name=_as_str("name", cmd.name),
            criticality=criticality,
            timeout_seconds=cmd.timeout_seconds,
            operation_template=operation_template,
            human_approval_config=human_approval_config,
            barrier_policy=barrier_policy,
            rollback_config=rollback_config,
            task_group_id=task_group_id,
            rollback_task_ref=rollback_task_ref,
        )

        now = _now()
        async with self._uow_factory() as uow:
            graph = await self._load_graph(uow, cmd.graph_id, tenant)
            graph.add_task(tenant, task, now)
            await uow.task_graphs.save(graph)
            await uow.commit()
        await self._publish_all(graph)
        return task_to_dto(task)

    async def add_dependency(self, cmd: AddDependencyCommand) -> None:
        tenant = self._tenant(cmd.tenant_id)
        try:
            predicate = DependencyPredicate(cmd.predicate)
        except ValueError as exc:
            raise ApplicationValidationError("predicate", f"invalid: {cmd.predicate}") from exc

        condition = ConditionalBranchConfig(
            predicate=predicate,
            objective_ref=cmd.objective_ref,
        )
        predecessor_id = CampaignTaskId(_as_uuid("predecessor_task_id", cmd.predecessor_task_id))
        successor_id = CampaignTaskId(_as_uuid("successor_task_id", cmd.successor_task_id))

        now = _now()
        async with self._uow_factory() as uow:
            graph = await self._load_graph(uow, cmd.graph_id, tenant)
            graph.add_dependency(tenant, predecessor_id, successor_id, condition, now)
            await uow.task_graphs.save(graph)
            await uow.commit()
        await self._publish_all(graph)

    async def validate_task_graph(
        self, cmd: ValidateTaskGraphCommand
    ) -> ValidationResultDTO:
        tenant = self._tenant(cmd.tenant_id)
        now = _now()
        async with self._uow_factory() as uow:
            graph = await self._load_graph(uow, cmd.graph_id, tenant)
            try:
                graph.validate(tenant, self._validator, now)
                await uow.task_graphs.save(graph)
                await uow.commit()
                await self._publish_all(graph)
                return ValidationResultDTO(is_valid=True, errors=[])
            except TaskGraphValidationFailed as exc:
                return ValidationResultDTO(is_valid=False, errors=exc.errors)

    async def sign_task_graph(self, cmd: SignTaskGraphCommand) -> None:
        tenant = self._tenant(cmd.tenant_id)
        signed_by = _as_str("signed_by", cmd.signed_by, 256)
        signature = _as_str("signature", cmd.signature, 1024)
        now = _now()
        async with self._uow_factory() as uow:
            graph = await self._load_graph(uow, cmd.graph_id, tenant)
            graph.sign(tenant, signed_by, signature, now)
            await uow.task_graphs.save(graph)
            await uow.commit()
        await self._publish_all(graph)

    async def activate_task_graph(self, cmd: ActivateTaskGraphCommand) -> None:
        tenant = self._tenant(cmd.tenant_id)
        now = _now()
        async with self._uow_factory() as uow:
            graph = await self._load_graph(uow, cmd.graph_id, tenant)
            graph.activate(tenant, now)
            await uow.task_graphs.save(graph)
            await uow.commit()
        await self._publish_all(graph)

    async def deprecate_task_graph(self, cmd: DeprecateTaskGraphCommand) -> None:
        tenant = self._tenant(cmd.tenant_id)
        now = _now()
        async with self._uow_factory() as uow:
            graph = await self._load_graph(uow, cmd.graph_id, tenant)
            graph.deprecate(tenant, now)
            await uow.task_graphs.save(graph)
            await uow.commit()
        await self._publish_all(graph)

    async def get_task_graph(self, query: GetTaskGraphQuery) -> TaskGraphDTO | None:
        tenant = self._tenant(query.tenant_id)
        async with self._uow_factory() as uow:
            gid = TaskGraphId(_as_uuid("graph_id", query.graph_id))
            graph = await uow.task_graphs.find_by_id(gid, tenant)
            if graph is None:
                return None
            return graph_to_dto(graph)

    async def get_execution_order(self, query: GetExecutionOrderQuery) -> ExecutionOrderDTO:
        tenant = self._tenant(query.tenant_id)
        async with self._uow_factory() as uow:
            graph = await self._load_graph(uow, query.graph_id, tenant)

        start_task_id: CampaignTaskId | None = None
        if query.start_task_id is not None:
            start_task_id = CampaignTaskId(_as_uuid("start_task_id", query.start_task_id))

        layers = self._resolver.resolve(graph, start_task_id)
        critical_path_duration = self._validator._compute_critical_path_duration(graph)
        return ExecutionOrderDTO(
            layers=[[str(tid) for tid in layer] for layer in layers],
            critical_path_duration_seconds=critical_path_duration,
        )
