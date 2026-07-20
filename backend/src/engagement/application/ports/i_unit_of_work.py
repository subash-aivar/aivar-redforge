"""IUnitOfWork — transactional boundary for Engagement application services."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import TracebackType

    from engagement.domain.repositories.i_engagement_repository import (
        IEngagementRepository,
    )
    from engagement.domain.repositories.i_target_authorization_repository import (
        ITargetAuthorizationRepository,
    )


class IUnitOfWork(ABC):
    engagements: IEngagementRepository
    target_authorizations: ITargetAuthorizationRepository

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
