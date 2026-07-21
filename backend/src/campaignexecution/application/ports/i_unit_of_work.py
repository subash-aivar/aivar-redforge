"""IUnitOfWork — abstract unit-of-work for campaignexecution context."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import TracebackType

    from campaignexecution.domain.repositories.i_campaign_safety_monitor_repository import (
        ICampaignSafetyMonitorRepository,
    )
    from campaignexecution.domain.repositories.i_task_graph_execution_repository import (
        ITaskGraphExecutionRepository,
    )


class IUnitOfWork(ABC):
    executions: ITaskGraphExecutionRepository
    safety_monitors: ICampaignSafetyMonitorRepository

    def __init__(self) -> None:
        self._committed = False

    @abstractmethod
    async def commit(self) -> None:
        self._committed = True

    @abstractmethod
    async def rollback(self) -> None: ...

    @abstractmethod
    async def __aenter__(self) -> IUnitOfWork: ...

    @abstractmethod
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...
