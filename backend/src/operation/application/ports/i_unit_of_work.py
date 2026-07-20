"""IUnitOfWork — transactional boundary for operation application services."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import TracebackType

    from operation.domain.repositories.i_execution_plan_version_repository import (
        IExecutionPlanVersionRepository,
    )
    from operation.domain.repositories.i_operation_repository import IOperationRepository


class IUnitOfWork(ABC):
    operations: IOperationRepository
    plan_versions: IExecutionPlanVersionRepository

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
