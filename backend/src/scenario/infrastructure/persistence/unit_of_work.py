"""PostgreSQL Unit of Work for scenario context."""

from __future__ import annotations

from typing import TYPE_CHECKING

from scenario.application.ports.i_unit_of_work import IUnitOfWork
from scenario.infrastructure.persistence.repositories.pg_scenario_template_repository import (
    PgScenarioTemplateRepository,
)

if TYPE_CHECKING:
    from types import TracebackType

    from sqlalchemy.ext.asyncio import AsyncSession


class PgUnitOfWork(IUnitOfWork):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__()
        self._session = session
        self.templates = PgScenarioTemplateRepository(session)

    async def commit(self) -> None:
        await self._session.commit()
        self._committed = True

    async def rollback(self) -> None:
        await self._session.rollback()

    async def __aenter__(self) -> PgUnitOfWork:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if exc_type is not None or not self._committed:
            await self.rollback()
