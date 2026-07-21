"""PostgreSQL Unit of Work for campaignexecution context."""

from __future__ import annotations

from typing import TYPE_CHECKING

from campaignexecution.application.ports.i_unit_of_work import IUnitOfWork
from campaignexecution.infrastructure.persistence.repositories.pg_safety_monitor_repository import (
    PgSafetyMonitorRepository,
)
from campaignexecution.infrastructure.persistence.repositories.pg_task_graph_execution_repository import (  # noqa: E501
    PgTaskGraphExecutionRepository,
)

if TYPE_CHECKING:
    from types import TracebackType

    from sqlalchemy.ext.asyncio import AsyncSession


class PgUnitOfWork(IUnitOfWork):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        super().__init__()

    async def __aenter__(self) -> PgUnitOfWork:
        self.executions = PgTaskGraphExecutionRepository(self._session)
        self.safety_monitors = PgSafetyMonitorRepository(self._session)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if exc_type is not None:
            await self.rollback()
        else:
            if not self._committed:
                await self.rollback()

    async def commit(self) -> None:
        await self._session.commit()
        await super().commit()

    async def rollback(self) -> None:
        await self._session.rollback()
