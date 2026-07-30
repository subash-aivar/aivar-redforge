"""SqlAlchemyUnitOfWork — transactional boundary implementation of the
`IUnitOfWork` ABC (M48C), following `OperationUnitOfWork`'s (and
`CredentialVaultUnitOfWork`'s) precedent exactly: `__aenter__` opens
an `AsyncSession` and constructs the context's repositories on
`self`, `commit`/`rollback` `await` real I/O on the session, and
`__aexit__` rolls back and closes if `commit()` was never called.

Converted from a sync-`Session`-over-`psycopg` implementation to a
genuinely async `AsyncSession`-over-`asyncpg` implementation in the
M48C contract correction — see `docs/architecture/m48/M48E_ADR.md`
for the deviation this resolves. There is no remaining deviation from
mature-context convention: `commit`/`rollback` now `await
self._session.commit()`/`rollback()` exactly like every other
bounded context's UnitOfWork.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from risk_engine.application.ports.i_unit_of_work import IUnitOfWork
from risk_engine.infrastructure.persistence.repositories.pg_risk_correlation_repository import (
    PgRiskCorrelationRepository,
)
from risk_engine.infrastructure.persistence.repositories.pg_risk_profile_repository import (
    PgEnterpriseRiskProfileRepository,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class SqlAlchemyUnitOfWork(IUnitOfWork):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        super().__init__()
        self._session_factory = session_factory
        self._session: AsyncSession | None = None

    async def __aenter__(self) -> SqlAlchemyUnitOfWork:
        self._session = self._session_factory()
        self.risk_profiles = PgEnterpriseRiskProfileRepository(self._session)
        self.correlation_sets = PgRiskCorrelationRepository(self._session)
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


def make_sqlalchemy_uow_factory(
    session_factory: async_sessionmaker[AsyncSession],
) -> Callable[[], SqlAlchemyUnitOfWork]:
    def factory() -> SqlAlchemyUnitOfWork:
        return SqlAlchemyUnitOfWork(session_factory)

    return factory
