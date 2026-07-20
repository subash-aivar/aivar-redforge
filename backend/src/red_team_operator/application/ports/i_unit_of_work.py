"""IUnitOfWork — transactional boundary for Operator application services."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import TracebackType

    from red_team_operator.domain.repositories.i_red_team_operator_repository import (
        IRedTeamOperatorRepository,
    )


class IUnitOfWork(ABC):
    """
    Unit of Work coordinating repository access within a single transaction.

    Subclasses must call ``super().__init__()`` so ``_committed`` is initialized.
    Concrete ``commit()`` implementations must set ``self._committed = True``
    after a successful commit.
    """

    operators: IRedTeamOperatorRepository

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
        """Persist all changes in the unit of work."""
        self._committed = True

    @abstractmethod
    async def rollback(self) -> None:
        """Discard all uncommitted changes in the unit of work."""
