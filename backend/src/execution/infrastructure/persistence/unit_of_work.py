"""ExecutionUnitOfWork — transactional boundary for execution repositories."""

from __future__ import annotations

from typing import TYPE_CHECKING

from execution.application.ports.i_unit_of_work import IUnitOfWork
from execution.infrastructure.persistence.repositories.pg_attack_action_repository import (
    PgAttackActionRepository,
)
from execution.infrastructure.persistence.repositories.pg_execution_journal_repository import (
    PgExecutionJournalRepository,
)
from execution.infrastructure.persistence.repositories.pg_execution_worker_repository import (
    PgExecutionWorkerRepository,
)
from execution.infrastructure.persistence.repositories.pg_kill_switch_repository import (
    PgKillSwitchRepository,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class ExecutionUnitOfWork(IUnitOfWork):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        super().__init__()
        self._session_factory = session_factory
        self._session: AsyncSession | None = None

    async def __aenter__(self) -> ExecutionUnitOfWork:
        self._session = self._session_factory()
        assert self._session is not None
        self.kill_switches = PgKillSwitchRepository(self._session)
        self.journals = PgExecutionJournalRepository(self._session)
        self.attack_actions = PgAttackActionRepository(self._session)
        self.workers = PgExecutionWorkerRepository(self._session)
        return self

    async def commit(self) -> None:
        if self._session is None:
            return
        await self._session.commit()
        self._committed = True

    async def rollback(self) -> None:
        if self._session is not None:
            await self._session.rollback()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if not self._committed and self._session is not None:
            await self._session.rollback()
        if self._session is not None:
            await self._session.close()
            self._session = None


def make_execution_uow_factory(
    session_factory: async_sessionmaker[AsyncSession],
) -> Callable[[], ExecutionUnitOfWork]:
    def factory() -> ExecutionUnitOfWork:
        return ExecutionUnitOfWork(session_factory)

    return factory
