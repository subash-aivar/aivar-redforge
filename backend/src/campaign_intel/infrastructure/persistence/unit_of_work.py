"""SqlAlchemyUnitOfWork — transactional boundary implementation of
`IUnitOfWork`, mirroring `malware_intel.infrastructure.persistence.
unit_of_work.SqlAlchemyUnitOfWork` exactly."""

from __future__ import annotations

from typing import TYPE_CHECKING

from campaign_intel.application.ports.i_unit_of_work import IUnitOfWork
from campaign_intel.infrastructure.persistence.repositories.pg_campaign_repository import (
    PgCampaignRepository,
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
        self.campaigns = PgCampaignRepository(self._session)
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
