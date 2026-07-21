"""IUnitOfWork — transactional boundary for TaskGraph application services."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import TracebackType

    from taskgraph.domain.repositories.i_task_graph_repository import ITaskGraphRepository


class IUnitOfWork(ABC):
    task_graphs: ITaskGraphRepository

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
    async def rollback(self) -> None:
        """Discard uncommitted changes."""
