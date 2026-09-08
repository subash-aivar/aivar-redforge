"""IUnitOfWork — mirrors `threat_actor_intel`'s `IUnitOfWork` shape
exactly: a repository attribute as a class-level annotation, async
commit/rollback/context-manager protocol. No concrete implementation
exists yet (Phase A3+) — this phase defines the contract only."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from ioc_intelligence.application.ports.i_ioc_repository import IIocRepository


class IUnitOfWork(ABC):
    iocs: IIocRepository

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
