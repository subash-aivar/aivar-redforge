"""CampaignUnitOfWork — transactional boundary for campaign repositories."""

from __future__ import annotations

from typing import TYPE_CHECKING

from campaign.application.ports.i_unit_of_work import IUnitOfWork
from campaign.infrastructure.persistence.repositories.pg_campaign_instance_repository import (
    PgCampaignInstanceRepository,
)
from campaign.infrastructure.persistence.repositories.pg_campaign_repository import (
    PgCampaignRepository,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class CampaignUnitOfWork(IUnitOfWork):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        super().__init__()
        self._session_factory = session_factory
        self._session: AsyncSession | None = None

    async def __aenter__(self) -> CampaignUnitOfWork:
        self._session = self._session_factory()
        assert self._session is not None
        self.campaigns = PgCampaignRepository(self._session)
        self.campaign_instances = PgCampaignInstanceRepository(self._session)
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


def make_campaign_uow_factory(
    session_factory: async_sessionmaker[AsyncSession],
) -> Callable[[], CampaignUnitOfWork]:
    def factory() -> CampaignUnitOfWork:
        return CampaignUnitOfWork(session_factory)

    return factory
