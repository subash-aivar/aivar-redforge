"""TaskGraph aggregate root — campaign task graph authoring and lifecycle."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from taskgraph.domain.entities.task_graph_entities import CampaignTask, TaskDependency
from taskgraph.domain.events.task_graph_events import (
    ConditionalBranchAdded,
    DependencyAdded,
    TaskAdded,
    TaskGraphActivated,
    TaskGraphCreated,
    TaskGraphDeprecated,
    TaskGraphSigned,
    TaskGraphValidated,
    TaskRemoved,
)
from taskgraph.domain.exceptions.domain_exceptions import (
    DuplicateTask,
    InvalidArgument,
    InvalidStateTransition,
    SignedGraphImmutabilityViolation,
    TaskGraphValidationFailed,
    TaskNotFound,
    TenantMismatch,
)
from taskgraph.domain.value_objects.enums import DependencyPredicate, TaskGraphState
from taskgraph.domain.value_objects.identifiers import TaskGraphId
from taskgraph.domain.value_objects.task_graph_vos import (
    ConditionalBranchConfig,
    TaskGraphVersion,
)

if TYPE_CHECKING:
    from datetime import datetime

    from taskgraph.domain.events.base import BaseDomainEvent
    from taskgraph.domain.services.task_graph_validator import TaskGraphValidator
    from taskgraph.domain.value_objects.identifiers import CampaignTaskId, TenantId

_ALLOWED_TRANSITIONS: dict[TaskGraphState, frozenset[TaskGraphState]] = {
    TaskGraphState.DRAFT: frozenset({TaskGraphState.VALIDATED}),
    TaskGraphState.VALIDATED: frozenset({TaskGraphState.SIGNED, TaskGraphState.DRAFT}),
    TaskGraphState.SIGNED: frozenset({TaskGraphState.ACTIVE}),
    TaskGraphState.ACTIVE: frozenset({TaskGraphState.DEPRECATED}),
    TaskGraphState.DEPRECATED: frozenset(),
}

_IMMUTABLE_STATES: frozenset[TaskGraphState] = frozenset(
    {TaskGraphState.SIGNED, TaskGraphState.ACTIVE, TaskGraphState.DEPRECATED}
)


class TaskGraph:
    """Aggregate root for the campaign task graph bounded context."""

    __slots__ = (
        "_pending_events",
        "_version",
        "created_at",
        "dependencies",
        "description",
        "engagement_window_seconds",
        "graph_id",
        "name",
        "signature",
        "signed_at",
        "signed_by",
        "state",
        "tasks",
        "tenant_id",
        "updated_at",
        "version",
    )

    def __init__(
        self,
        graph_id: TaskGraphId,
        tenant_id: TenantId,
        name: str,
        description: str,
        state: TaskGraphState,
        version: TaskGraphVersion,
        tasks: list[CampaignTask],
        dependencies: list[TaskDependency],
        engagement_window_seconds: int,
        signed_by: str | None,
        signed_at: datetime | None,
        signature: str | None,
        created_at: datetime,
        updated_at: datetime,
        row_version: int,
    ) -> None:
        self.graph_id = graph_id
        self.tenant_id = tenant_id
        self.name = name
        self.description = description
        self.state = state
        self.version = version
        self.tasks = list(tasks)
        self.dependencies = list(dependencies)
        self.engagement_window_seconds = engagement_window_seconds
        self.signed_by = signed_by
        self.signed_at = signed_at
        self.signature = signature
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = row_version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def row_version(self) -> int:
        return self._version

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _assert_topology_mutable(self) -> None:
        if self.state in _IMMUTABLE_STATES:
            raise SignedGraphImmutabilityViolation(str(self.graph_id))

    def _mutate(self, now: datetime) -> None:
        self.updated_at = now
        self._version += 1

    def _transition(self, to_state: TaskGraphState) -> None:
        allowed = _ALLOWED_TRANSITIONS.get(self.state, frozenset())
        if to_state not in allowed:
            raise InvalidStateTransition(
                self.state.value,
                to_state.value,
                str(self.graph_id),
            )
        self.state = to_state

    def _task_ids(self) -> frozenset[CampaignTaskId]:
        return frozenset(t.task_id for t in self.tasks)

    @classmethod
    def create(
        cls,
        graph_id: TaskGraphId,
        tenant_id: TenantId,
        name: str,
        description: str,
        engagement_window_seconds: int,
        now: datetime,
    ) -> TaskGraph:
        if not name.strip():
            raise InvalidArgument("name", "must not be empty")
        if engagement_window_seconds <= 0:
            raise InvalidArgument(
                "engagement_window_seconds", "must be positive"
            )
        graph = cls(
            graph_id=graph_id,
            tenant_id=tenant_id,
            name=name.strip(),
            description=description.strip(),
            state=TaskGraphState.DRAFT,
            version=TaskGraphVersion(1, 0, 0),
            tasks=[],
            dependencies=[],
            engagement_window_seconds=engagement_window_seconds,
            signed_by=None,
            signed_at=None,
            signature=None,
            created_at=now,
            updated_at=now,
            row_version=1,
        )
        graph._emit(
            TaskGraphCreated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(graph_id),
                aggregate_type="TaskGraph",
                name=name.strip(),
                tenant_id_str=str(tenant_id),
            )
        )
        return graph

    def add_task(
        self,
        tenant_id: TenantId,
        task: CampaignTask,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_topology_mutable()
        if task.task_id in self._task_ids():
            raise DuplicateTask(str(task.task_id))
        if not task.name.strip():
            raise InvalidArgument("task.name", "must not be empty")
        self.tasks.append(task)
        self._mutate(now)
        self._emit(
            TaskAdded(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.graph_id),
                aggregate_type="TaskGraph",
                task_id=str(task.task_id),
                task_type=task.task_type.value,
                criticality=task.criticality.value,
            )
        )

    def remove_task(
        self,
        tenant_id: TenantId,
        task_id: CampaignTaskId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_topology_mutable()
        found = next((t for t in self.tasks if t.task_id == task_id), None)
        if found is None:
            raise TaskNotFound(str(task_id))
        self.tasks.remove(found)
        # Remove all dependencies referencing this task
        self.dependencies = [
            d
            for d in self.dependencies
            if d.predecessor_id != task_id and d.successor_id != task_id
        ]
        self._mutate(now)
        self._emit(
            TaskRemoved(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.graph_id),
                aggregate_type="TaskGraph",
                task_id=str(task_id),
            )
        )

    def add_dependency(
        self,
        tenant_id: TenantId,
        predecessor_id: CampaignTaskId,
        successor_id: CampaignTaskId,
        condition: ConditionalBranchConfig,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_topology_mutable()
        task_ids = self._task_ids()
        if predecessor_id not in task_ids:
            raise TaskNotFound(str(predecessor_id))
        if successor_id not in task_ids:
            raise TaskNotFound(str(successor_id))
        if predecessor_id == successor_id:
            raise InvalidArgument(
                "predecessor_id", "task cannot depend on itself"
            )
        dep = TaskDependency(
            predecessor_id=predecessor_id,
            successor_id=successor_id,
            condition=condition,
        )
        self.dependencies.append(dep)
        self._mutate(now)
        is_conditional = condition.predicate not in {
            DependencyPredicate.ALWAYS_EXECUTE,
            DependencyPredicate.EXECUTE_ON_SUCCESS,
            DependencyPredicate.EXECUTE_ON_FAILURE,
        }
        if is_conditional:
            self._emit(
                ConditionalBranchAdded(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=self.tenant_id,
                    aggregate_id=str(self.graph_id),
                    aggregate_type="TaskGraph",
                    predecessor_id=str(predecessor_id),
                    successor_id=str(successor_id),
                    predicate=condition.predicate.value,
                    objective_ref=condition.objective_ref,
                )
            )
        else:
            self._emit(
                DependencyAdded(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=self.tenant_id,
                    aggregate_id=str(self.graph_id),
                    aggregate_type="TaskGraph",
                    predecessor_id=str(predecessor_id),
                    successor_id=str(successor_id),
                    predicate=condition.predicate.value,
                )
            )

    def validate(
        self,
        tenant_id: TenantId,
        validator: TaskGraphValidator,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not self.tasks:
            raise InvalidArgument("tasks", "graph must have at least one task")
        if self.state not in {TaskGraphState.DRAFT, TaskGraphState.VALIDATED}:
            raise InvalidStateTransition(
                self.state.value, TaskGraphState.VALIDATED.value, str(self.graph_id)
            )
        errors = validator.validate(self)
        if errors:
            raise TaskGraphValidationFailed(str(self.graph_id), errors)
        self.state = TaskGraphState.VALIDATED
        self._mutate(now)
        self._emit(
            TaskGraphValidated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.graph_id),
                aggregate_type="TaskGraph",
                task_count=len(self.tasks),
                dependency_count=len(self.dependencies),
            )
        )

    def sign(
        self,
        tenant_id: TenantId,
        signed_by: str,
        signature: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.state != TaskGraphState.VALIDATED:
            raise InvalidStateTransition(
                self.state.value, TaskGraphState.SIGNED.value, str(self.graph_id)
            )
        if not signed_by.strip():
            raise InvalidArgument("signed_by", "must not be empty")
        if not signature.strip():
            raise InvalidArgument("signature", "must not be empty")
        self.signed_by = signed_by.strip()
        self.signed_at = now
        self.signature = signature.strip()
        self._transition(TaskGraphState.SIGNED)
        self._mutate(now)
        self._emit(
            TaskGraphSigned(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.graph_id),
                aggregate_type="TaskGraph",
                signed_by=signed_by.strip(),
                version_str=str(self.version),
            )
        )

    def activate(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(TaskGraphState.ACTIVE)
        self._mutate(now)
        self._emit(
            TaskGraphActivated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.graph_id),
                aggregate_type="TaskGraph",
            )
        )

    def deprecate(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(TaskGraphState.DEPRECATED)
        self._mutate(now)
        self._emit(
            TaskGraphDeprecated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.graph_id),
                aggregate_type="TaskGraph",
            )
        )
