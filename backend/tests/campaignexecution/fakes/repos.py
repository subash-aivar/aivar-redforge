"""In-memory fake repositories for campaignexecution tests."""

from __future__ import annotations

from types import TracebackType
from typing import TYPE_CHECKING

from campaignexecution.application.ports.i_event_publisher import IEventPublisher
from campaignexecution.application.ports.i_unit_of_work import IUnitOfWork
from campaignexecution.domain.repositories.i_campaign_safety_monitor_repository import (
    ICampaignSafetyMonitorRepository,
)
from campaignexecution.domain.repositories.i_task_graph_execution_repository import (
    ITaskGraphExecutionRepository,
)

if TYPE_CHECKING:
    from campaignexecution.domain.aggregates.campaign_safety_monitor import CampaignSafetyMonitor
    from campaignexecution.domain.aggregates.task_graph_execution import TaskGraphExecution
    from campaignexecution.domain.entities.execution_entities import TaskExecutionRecord
    from campaignexecution.domain.events.base import BaseDomainEvent
    from campaignexecution.domain.value_objects.identifiers import (
        CampaignInstanceId,
        TaskGraphExecutionId,
        TenantId,
    )


class FakeTaskGraphExecutionRepository(ITaskGraphExecutionRepository):
    def __init__(self) -> None:
        self._store: dict[str, TaskGraphExecution] = {}

    async def save(self, execution: TaskGraphExecution) -> None:
        self._store[str(execution.execution_id)] = execution

    async def find_by_id(
        self,
        execution_id: TaskGraphExecutionId,
        tenant_id: TenantId,
    ) -> TaskGraphExecution | None:
        return self._store.get(str(execution_id))

    async def find_by_campaign_instance(
        self,
        instance_id: CampaignInstanceId,
        tenant_id: TenantId,
    ) -> TaskGraphExecution | None:
        for exec_ in self._store.values():
            if exec_.campaign_instance_ref.instance_id == instance_id.value:
                return exec_
        return None

    async def find_pending_dispatch_by_tenant(
        self,
        tenant_id: TenantId,
    ) -> list[TaskExecutionRecord]:
        from campaignexecution.domain.value_objects.enums import TaskExecutionState

        records = []
        for exec_ in self._store.values():
            if exec_.tenant_id == tenant_id:
                records.extend(
                    r for r in exec_.task_records
                    if r.state == TaskExecutionState.READY_TO_DISPATCH
                )
        return records


class FakeSafetyMonitorRepository(ICampaignSafetyMonitorRepository):
    def __init__(self) -> None:
        self._store: dict[str, CampaignSafetyMonitor] = {}

    async def save(self, monitor: CampaignSafetyMonitor) -> None:
        key = str(monitor.campaign_instance_ref.instance_id)
        self._store[key] = monitor

    async def find_by_campaign_instance(
        self,
        instance_id: CampaignInstanceId,
        tenant_id: TenantId,
    ) -> CampaignSafetyMonitor | None:
        return self._store.get(str(instance_id.value))


class FakeEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.published: list[BaseDomainEvent] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.published.extend(events)


class FakeUnitOfWork(IUnitOfWork):
    def __init__(self) -> None:
        self.executions = FakeTaskGraphExecutionRepository()
        self.safety_monitors = FakeSafetyMonitorRepository()
        super().__init__()

    async def __aenter__(self) -> FakeUnitOfWork:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if exc_type is not None:
            await self.rollback()

    async def commit(self) -> None:
        await super().commit()

    async def rollback(self) -> None:
        pass
