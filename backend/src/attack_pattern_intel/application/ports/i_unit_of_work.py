"""IUnitOfWork — mirrors `ioc_intelligence.application.ports.
i_unit_of_work.IUnitOfWork`'s shape exactly."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from attack_pattern_intel.application.ports.i_attack_pattern_repository import (
        IAttackPatternRepository,
    )


class IUnitOfWork(ABC):
    attack_patterns: IAttackPatternRepository

    @abstractmethod
    async def commit(self) -> None: ...

    @abstractmethod
    async def rollback(self) -> None: ...

    @abstractmethod
    async def __aenter__(self) -> Self: ...

    @abstractmethod
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None: ...
