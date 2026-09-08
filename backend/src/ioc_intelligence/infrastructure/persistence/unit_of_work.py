"""SqlAlchemyUnitOfWork — transactional boundary implementation of
`IUnitOfWork` (M51.2 Phase A3), mirroring `threat_actor_intel.
infrastructure.persistence.unit_of_work.SqlAlchemyUnitOfWork` exactly:
`__aenter__` opens an `AsyncSession` and constructs the context's
repository on `self`; `commit`/`rollback` `await` real I/O on the
session; `__aexit__` rolls back and closes if `commit()` was never
called. Transaction ownership lives here, not in the repository —
`PgIocRepository` never calls `session.commit()`/`session.rollback()`
itself except to unwind a single failed statement it is translating
into a domain-safe exception, which still leaves the outer transaction
boundary owned by this class."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ioc_intelligence.application.ports.i_unit_of_work import IUnitOfWork
from ioc_intelligence.infrastructure.persistence.repositories.pg_ioc_repository import (
    PgIocRepository,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class SqlAlchemyUnitOfWork(IUnitOfWork):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        super().__init__()
        self._session_factory = session_factory
        self._session: AsyncSession | None = None
        self._committed = False

    async def __aenter__(self) -> SqlAlchemyUnitOfWork:
        self._session = self._session_factory()
        self.iocs = PgIocRepository(self._session)
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
        exc_tb: object,
    ) -> None:
        if not self._committed and self._session is not None:
            await self._session.rollback()
        if self._session is not None:
            await self._session.close()
            self._session = None


def make_sqlalchemy_uow_factory(
    session_factory: async_sessionmaker[AsyncSession],
) -> Callable[[], SqlAlchemyUnitOfWork]:
    def factory() -> SqlAlchemyUnitOfWork:
        return SqlAlchemyUnitOfWork(session_factory)

    return factory
