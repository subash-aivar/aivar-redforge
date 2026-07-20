"""In-memory fakes for operation application / repository contract tests."""

from __future__ import annotations

from types import TracebackType
from typing import Self
from uuid import UUID

from operation.application.ports.i_event_publisher import IEventPublisher
from operation.application.ports.i_unit_of_work import IUnitOfWork
from operation.domain.aggregates.execution_plan_version import ExecutionPlanVersion
from operation.domain.aggregates.operation import Operation
from operation.domain.events.base import BaseDomainEvent
from operation.domain.ports.i_engagement_query_port import IEngagementQueryPort
from operation.domain.ports.i_vulnerability_query_port import (
    AttackSurfaceContext,
    IVulnerabilityQueryPort,
)
from operation.domain.repositories.i_execution_plan_version_repository import (
    IExecutionPlanVersionRepository,
)
from operation.domain.repositories.i_operation_repository import IOperationRepository
from operation.domain.value_objects.enums import ExecutionPlanVersionState
from operation.domain.value_objects.identifiers import (
    EngagementId,
    ExecutionPlanVersionId,
    OperationId,
    TenantId,
)


class InMemoryOperationRepository(IOperationRepository):
    def __init__(self) -> None:
        self.by_id: dict[tuple[UUID, UUID], Operation] = {}

    async def save(self, operation: Operation) -> None:
        self.by_id[(operation.operation_id.value, operation.tenant_id.value)] = operation

    async def find_by_id(
        self,
        operation_id: OperationId,
        tenant_id: TenantId,
    ) -> Operation | None:
        return self.by_id.get((operation_id.value, tenant_id.value))

    async def find_by_engagement(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Operation]:
        items = [
            o
            for o in self.by_id.values()
            if o.tenant_id == tenant_id and o.engagement_id == engagement_id
        ]
        return items[offset : offset + limit]


class InMemoryPlanVersionRepository(IExecutionPlanVersionRepository):
    def __init__(self) -> None:
        self.by_id: dict[tuple[UUID, UUID], ExecutionPlanVersion] = {}

    async def save(self, plan_version: ExecutionPlanVersion) -> None:
        self.by_id[
            (plan_version.plan_version_id.value, plan_version.tenant_id.value)
        ] = plan_version

    async def find_by_id(
        self,
        plan_version_id: ExecutionPlanVersionId,
        tenant_id: TenantId,
    ) -> ExecutionPlanVersion | None:
        return self.by_id.get((plan_version_id.value, tenant_id.value))

    async def find_by_operation(
        self,
        operation_id: OperationId,
        tenant_id: TenantId,
    ) -> list[ExecutionPlanVersion]:
        return [
            p
            for p in self.by_id.values()
            if p.tenant_id == tenant_id and p.operation_id == operation_id
        ]

    async def find_executing_for_operation(
        self,
        operation_id: OperationId,
        tenant_id: TenantId,
    ) -> ExecutionPlanVersion | None:
        for p in await self.find_by_operation(operation_id, tenant_id):
            if p.state == ExecutionPlanVersionState.EXECUTING:
                return p
        return None

    async def next_version_number(
        self,
        operation_id: OperationId,
        tenant_id: TenantId,
    ) -> int:
        existing = await self.find_by_operation(operation_id, tenant_id)
        if not existing:
            return 1
        return max(p.version_number for p in existing) + 1

    async def find_referencing_payload(
        self,
        tenant_id: TenantId,
        payload_id: str,
    ) -> list[ExecutionPlanVersion]:
        return [
            p
            for p in self.by_id.values()
            if p.tenant_id == tenant_id and payload_id in p.snapshot.value
        ]


class FakeOperationUnitOfWork(IUnitOfWork):
    def __init__(
        self,
        operations: InMemoryOperationRepository | None = None,
        plan_versions: InMemoryPlanVersionRepository | None = None,
    ) -> None:
        super().__init__()
        self.operations = operations or InMemoryOperationRepository()
        self.plan_versions = plan_versions or InMemoryPlanVersionRepository()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if not self._committed:
            await self.rollback()

    async def commit(self) -> None:
        self._committed = True

    async def rollback(self) -> None:
        self._committed = False


class FakeEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.published: list[BaseDomainEvent] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.published.extend(events)


class FakeEngagementQueryPort(IEngagementQueryPort):
    def __init__(
        self,
        *,
        state: str = "Active",
        active: bool = True,
        targets: set[UUID] | None = None,
        techniques: set[str] | None = None,
    ) -> None:
        self.state = state
        self.active = active
        self.targets = targets or set()
        self.techniques = techniques or {"T1059", "T1021"}

    async def get_engagement_state(
        self, engagement_id: EngagementId, tenant_id: TenantId
    ) -> str:
        return self.state

    async def is_active(self, engagement_id: EngagementId, tenant_id: TenantId) -> bool:
        return self.active

    async def get_authorized_targets(
        self, engagement_id: EngagementId, tenant_id: TenantId
    ) -> set[UUID]:
        return set(self.targets)

    async def get_allowed_techniques(
        self, engagement_id: EngagementId, tenant_id: TenantId
    ) -> set[str]:
        return set(self.techniques)


class FakeVulnerabilityQueryPort(IVulnerabilityQueryPort):
    async def get_attack_surface_context(
        self, engagement_id: EngagementId, tenant_id: TenantId
    ) -> AttackSurfaceContext:
        return AttackSurfaceContext(
            vulnerability_instance_refs=(),
            technique_hints=(),
            degraded=True,
        )
