"""IUnitOfWork and IEventPublisher for the execution context."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import TracebackType

    from execution.domain.events.base import BaseDomainEvent
    from execution.domain.repositories.i_repositories import (
        IAttackActionRepository,
        IExecutionJournalRepository,
        IExecutionWorkerRepository,
        IKillSwitchRepository,
    )


class IUnitOfWork(ABC):
    kill_switches: IKillSwitchRepository
    journals: IExecutionJournalRepository
    attack_actions: IAttackActionRepository
    workers: IExecutionWorkerRepository

    def __init__(self) -> None:
        self._committed = False

    async def __aenter__(self) -> IUnitOfWork:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if not self._committed:
            await self.rollback()

    @abstractmethod
    async def commit(self) -> None:
        self._committed = True

    @abstractmethod
    async def rollback(self) -> None: ...


class IEventPublisher(ABC):
    @abstractmethod
    async def publish_batch(self, events: list[BaseDomainEvent]) -> None: ...
