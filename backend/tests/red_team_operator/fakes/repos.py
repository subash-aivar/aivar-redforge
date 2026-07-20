"""In-memory fakes for RedTeamOperator application tests."""

from __future__ import annotations

from types import TracebackType
from typing import Self
from uuid import UUID

from red_team_operator.application.ports.i_event_publisher import IEventPublisher
from red_team_operator.application.ports.i_unit_of_work import IUnitOfWork
from red_team_operator.domain.aggregates.red_team_operator import RedTeamOperator
from red_team_operator.domain.events.base import BaseDomainEvent
from red_team_operator.domain.repositories.i_red_team_operator_repository import (
    IRedTeamOperatorRepository,
)
from red_team_operator.domain.value_objects.enums import ApprovalScope, OperatorState
from red_team_operator.domain.value_objects.identifiers import OperatorId, TenantId


class InMemoryOperatorRepository(IRedTeamOperatorRepository):
    def __init__(self) -> None:
        self.by_id: dict[UUID, RedTeamOperator] = {}

    async def save(self, op: RedTeamOperator) -> None:
        self.by_id[op.operator_id.value] = op

    async def find_by_id(self, operator_id: OperatorId) -> RedTeamOperator | None:
        return self.by_id.get(operator_id.value)

    async def find_authorized_approvers(
        self,
        scope: ApprovalScope,
        tenant_id: TenantId,
    ) -> list[RedTeamOperator]:
        return [
            op
            for op in self.by_id.values()
            if op.tenant_id == tenant_id
            and op.state == OperatorState.ACTIVE
            and op.approval_authority.includes(scope)
        ]

    async def find_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        include_inactive: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RedTeamOperator]:
        items = [
            op
            for op in self.by_id.values()
            if op.tenant_id == tenant_id
            and (include_inactive or op.state == OperatorState.ACTIVE)
        ]
        return items[offset : offset + limit]


class FakeOperatorUnitOfWork(IUnitOfWork):
    def __init__(self, operators: InMemoryOperatorRepository | None = None) -> None:
        super().__init__()
        self.operators = operators or InMemoryOperatorRepository()

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
