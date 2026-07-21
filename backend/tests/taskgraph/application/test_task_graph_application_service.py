"""TaskGraph application service tests — CRUD, validate, sign, activate."""

from __future__ import annotations

from types import TracebackType
from uuid import uuid4

import pytest

from taskgraph.application.commands.task_graph_commands import (
    ActivateTaskGraphCommand,
    AddDependencyCommand,
    AddTaskCommand,
    CreateTaskGraphCommand,
    GetExecutionOrderQuery,
    GetTaskGraphQuery,
    SignTaskGraphCommand,
    ValidateTaskGraphCommand,
)
from taskgraph.application.exceptions import (
    ApplicationValidationError,
)
from taskgraph.application.ports.i_event_publisher import IEventPublisher
from taskgraph.application.ports.i_unit_of_work import IUnitOfWork
from taskgraph.application.services.task_graph_application_service import (
    TaskGraphApplicationService,
)
from taskgraph.domain.events.base import BaseDomainEvent
from taskgraph.domain.repositories.i_task_graph_repository import ITaskGraphRepository
from taskgraph.domain.value_objects.identifiers import TenantId
from tests.taskgraph.fakes.repos import FakeTaskGraphRepository


class FakeUnitOfWork(IUnitOfWork):
    def __init__(self, task_graphs: ITaskGraphRepository) -> None:
        super().__init__()
        self.task_graphs = task_graphs  # type: ignore[assignment]
        self.committed = False

    async def commit(self) -> None:
        self._committed = True
        self.committed = True

    async def rollback(self) -> None:
        pass

    async def __aenter__(self) -> FakeUnitOfWork:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if not self._committed:
            await self.rollback()


class FakeEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.published: list[BaseDomainEvent] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.published.extend(events)


def make_service(
    tenant_id: TenantId,
) -> tuple[TaskGraphApplicationService, FakeUnitOfWork, FakeEventPublisher]:
    repo = FakeTaskGraphRepository()
    uow = FakeUnitOfWork(task_graphs=repo)
    publisher = FakeEventPublisher()

    def uow_factory() -> FakeUnitOfWork:
        return uow

    svc = TaskGraphApplicationService(
        uow_factory=uow_factory,
        event_publisher=publisher,
    )
    return svc, uow, publisher


class TestCreateTaskGraph:
    @pytest.mark.asyncio
    async def test_create_persists_and_returns_dto(self, tenant_id, now) -> None:
        svc, _, __ = make_service(tenant_id)
        cmd = CreateTaskGraphCommand(
            tenant_id=tenant_id.value,
            name="APT29 Kill Chain",
            description="Full kill chain simulation",
            engagement_window_seconds=86400,
        )
        dto = await svc.create_task_graph(cmd)
        assert dto.name == "APT29 Kill Chain"
        assert dto.state == "Draft"
        assert dto.task_count == 0

    @pytest.mark.asyncio
    async def test_create_empty_name_raises(self, tenant_id, now) -> None:
        svc, _, _ = make_service(tenant_id)
        cmd = CreateTaskGraphCommand(
            tenant_id=tenant_id.value,
            name="  ",
            description="",
            engagement_window_seconds=86400,
        )
        with pytest.raises(ApplicationValidationError):
            await svc.create_task_graph(cmd)

    @pytest.mark.asyncio
    async def test_get_nonexistent_returns_none(self, tenant_id, now) -> None:
        svc, _, _ = make_service(tenant_id)
        result = await svc.get_task_graph(
            GetTaskGraphQuery(
                tenant_id=tenant_id.value,
                graph_id=uuid4(),
            )
        )
        assert result is None


class TestAddTasksAndDependencies:
    @pytest.mark.asyncio
    async def test_add_task_increments_count(self, tenant_id, now) -> None:
        svc, _, __ = make_service(tenant_id)
        create_cmd = CreateTaskGraphCommand(
            tenant_id=tenant_id.value,
            name="Test Graph",
            description="",
            engagement_window_seconds=86400,
        )
        dto = await svc.create_task_graph(create_cmd)
        graph_id = dto.graph_id

        task_dto = await svc.add_task(
            AddTaskCommand(
                tenant_id=tenant_id.value,
                graph_id=graph_id,
                task_type="OperationTask",
                name="Initial Access",
                criticality="Required",
                timeout_seconds=300,
                technique_id="T1566.001",
                technique_name="Phishing",
                technique_parameters={},
            )
        )
        assert task_dto.name == "Initial Access"
        assert task_dto.task_type == "OperationTask"

        fetched = await svc.get_task_graph(
            GetTaskGraphQuery(tenant_id=tenant_id.value, graph_id=graph_id)
        )
        assert fetched is not None
        assert fetched.task_count == 1

    @pytest.mark.asyncio
    async def test_add_dependency_recorded(self, tenant_id, now) -> None:
        svc, _, __ = make_service(tenant_id)
        create_dto = await svc.create_task_graph(
            CreateTaskGraphCommand(
                tenant_id=tenant_id.value,
                name="Graph A",
                description="",
                engagement_window_seconds=86400,
            )
        )
        graph_id = create_dto.graph_id

        t1_dto = await svc.add_task(
            AddTaskCommand(
                tenant_id=tenant_id.value,
                graph_id=graph_id,
                task_type="OperationTask",
                name="T1",
                criticality="Required",
                timeout_seconds=300,
                technique_id="T1059",
                technique_name="Command Exec",
                technique_parameters={},
            )
        )
        t2_dto = await svc.add_task(
            AddTaskCommand(
                tenant_id=tenant_id.value,
                graph_id=graph_id,
                task_type="OperationTask",
                name="T2",
                criticality="Required",
                timeout_seconds=300,
                technique_id="T1059",
                technique_name="Command Exec",
                technique_parameters={},
            )
        )
        await svc.add_dependency(
            AddDependencyCommand(
                tenant_id=tenant_id.value,
                graph_id=graph_id,
                predecessor_task_id=t1_dto.task_id,
                successor_task_id=t2_dto.task_id,
                predicate="ExecuteOnSuccess",
            )
        )

        fetched = await svc.get_task_graph(
            GetTaskGraphQuery(tenant_id=tenant_id.value, graph_id=graph_id)
        )
        assert fetched is not None
        assert fetched.dependency_count == 1


class TestValidateSignActivate:
    @pytest.mark.asyncio
    async def test_full_lifecycle_draft_to_active(self, tenant_id, now) -> None:
        svc, _, __ = make_service(tenant_id)
        create_dto = await svc.create_task_graph(
            CreateTaskGraphCommand(
                tenant_id=tenant_id.value,
                name="Kill Chain",
                description="",
                engagement_window_seconds=86400,
            )
        )
        graph_id = create_dto.graph_id

        # Add a task
        await svc.add_task(
            AddTaskCommand(
                tenant_id=tenant_id.value,
                graph_id=graph_id,
                task_type="OperationTask",
                name="Recon",
                criticality="Required",
                timeout_seconds=300,
                technique_id="T1595",
                technique_name="Active Scanning",
                technique_parameters={},
            )
        )

        # Validate
        result = await svc.validate_task_graph(
            ValidateTaskGraphCommand(
                tenant_id=tenant_id.value,
                graph_id=graph_id,
            )
        )
        assert result.is_valid

        # Sign
        await svc.sign_task_graph(
            SignTaskGraphCommand(
                tenant_id=tenant_id.value,
                graph_id=graph_id,
                signed_by="operator-1",
                signature="sig-abc",
            )
        )

        # Activate
        await svc.activate_task_graph(
            ActivateTaskGraphCommand(
                tenant_id=tenant_id.value,
                graph_id=graph_id,
            )
        )

        fetched = await svc.get_task_graph(
            GetTaskGraphQuery(tenant_id=tenant_id.value, graph_id=graph_id)
        )
        assert fetched is not None
        assert fetched.state == "Active"
        assert fetched.signed_by == "operator-1"

    @pytest.mark.asyncio
    async def test_cyclic_graph_validation_reports_errors(self, tenant_id, now) -> None:
        svc, _, __ = make_service(tenant_id)
        create_dto = await svc.create_task_graph(
            CreateTaskGraphCommand(
                tenant_id=tenant_id.value,
                name="Cyclic Graph",
                description="",
                engagement_window_seconds=86400,
            )
        )
        graph_id = create_dto.graph_id

        t1 = await svc.add_task(
            AddTaskCommand(
                tenant_id=tenant_id.value,
                graph_id=graph_id,
                task_type="OperationTask",
                name="A",
                criticality="Required",
                timeout_seconds=100,
                technique_id="T1059",
                technique_name="Exec",
                technique_parameters={},
            )
        )
        t2 = await svc.add_task(
            AddTaskCommand(
                tenant_id=tenant_id.value,
                graph_id=graph_id,
                task_type="OperationTask",
                name="B",
                criticality="Required",
                timeout_seconds=100,
                technique_id="T1059",
                technique_name="Exec",
                technique_parameters={},
            )
        )
        # Create cycle: A→B and B→A
        await svc.add_dependency(
            AddDependencyCommand(
                tenant_id=tenant_id.value,
                graph_id=graph_id,
                predecessor_task_id=t1.task_id,
                successor_task_id=t2.task_id,
                predicate="AlwaysExecute",
            )
        )
        await svc.add_dependency(
            AddDependencyCommand(
                tenant_id=tenant_id.value,
                graph_id=graph_id,
                predecessor_task_id=t2.task_id,
                successor_task_id=t1.task_id,
                predicate="AlwaysExecute",
            )
        )

        result = await svc.validate_task_graph(
            ValidateTaskGraphCommand(
                tenant_id=tenant_id.value,
                graph_id=graph_id,
            )
        )
        assert not result.is_valid
        assert any("Cycle" in e for e in result.errors)


class TestExecutionOrderQuery:
    @pytest.mark.asyncio
    async def test_execution_order_diamond_graph(self, tenant_id, now) -> None:
        svc, _, __ = make_service(tenant_id)
        create_dto = await svc.create_task_graph(
            CreateTaskGraphCommand(
                tenant_id=tenant_id.value,
                name="Diamond",
                description="",
                engagement_window_seconds=86400,
            )
        )
        graph_id = create_dto.graph_id

        a = await svc.add_task(AddTaskCommand(tenant_id=tenant_id.value, graph_id=graph_id, task_type="OperationTask", name="A", criticality="Required", timeout_seconds=100, technique_id="T1", technique_name="T1", technique_parameters={}))
        b = await svc.add_task(AddTaskCommand(tenant_id=tenant_id.value, graph_id=graph_id, task_type="OperationTask", name="B", criticality="Required", timeout_seconds=100, technique_id="T1", technique_name="T1", technique_parameters={}))
        c = await svc.add_task(AddTaskCommand(tenant_id=tenant_id.value, graph_id=graph_id, task_type="OperationTask", name="C", criticality="Required", timeout_seconds=100, technique_id="T1", technique_name="T1", technique_parameters={}))
        d = await svc.add_task(AddTaskCommand(tenant_id=tenant_id.value, graph_id=graph_id, task_type="OperationTask", name="D", criticality="Required", timeout_seconds=100, technique_id="T1", technique_name="T1", technique_parameters={}))

        await svc.add_dependency(AddDependencyCommand(tenant_id=tenant_id.value, graph_id=graph_id, predecessor_task_id=a.task_id, successor_task_id=b.task_id, predicate="AlwaysExecute"))
        await svc.add_dependency(AddDependencyCommand(tenant_id=tenant_id.value, graph_id=graph_id, predecessor_task_id=a.task_id, successor_task_id=c.task_id, predicate="AlwaysExecute"))
        await svc.add_dependency(AddDependencyCommand(tenant_id=tenant_id.value, graph_id=graph_id, predecessor_task_id=b.task_id, successor_task_id=d.task_id, predicate="AlwaysExecute"))
        await svc.add_dependency(AddDependencyCommand(tenant_id=tenant_id.value, graph_id=graph_id, predecessor_task_id=c.task_id, successor_task_id=d.task_id, predicate="AlwaysExecute"))

        order_dto = await svc.get_execution_order(
            GetExecutionOrderQuery(tenant_id=tenant_id.value, graph_id=graph_id)
        )
        assert len(order_dto.layers) == 3
        assert str(a.task_id) in order_dto.layers[0]
        assert set(order_dto.layers[1]) == {str(b.task_id), str(c.task_id)}
        assert str(d.task_id) in order_dto.layers[2]
