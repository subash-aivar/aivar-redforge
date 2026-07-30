"""SqlAlchemyUnitOfWork — transactional boundary implementation of the
`IUnitOfWork` ABC (M49C), following
`risk_engine.infrastructure.persistence.unit_of_work.
SqlAlchemyUnitOfWork`'s precedent exactly: `__aenter__` opens an
`AsyncSession` and constructs the context's repositories on `self`,
`commit`/`rollback` `await` real I/O on the session, and `__aexit__`
rolls back and closes if `commit()` was never called."""

from __future__ import annotations

from typing import TYPE_CHECKING

from attack_surface_management.application.ports.i_unit_of_work import IUnitOfWork
from attack_surface_management.infrastructure.persistence.repositories.pg_asset_repository import (
    PgAssetRepository,
)
from attack_surface_management.infrastructure.persistence.repositories.pg_network_range_repository import (  # noqa: E501
    PgNetworkRangeRepository,
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
        self.assets = PgAssetRepository(self._session)
        self.network_ranges = PgNetworkRangeRepository(self._session)
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
