"""IUnitOfWork — mirrors `exposure.IUnitOfWork`'s shape exactly:
repository attributes as class-level annotations, async commit/
rollback/context-manager protocol. No concrete implementation exists
yet (Phase 3) — this phase defines the contract only."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from threat_actor_intel.domain.repositories.i_threat_actor_association_repository import (
        IThreatActorAssociationRepository,
    )
    from threat_actor_intel.domain.repositories.i_threat_actor_repository import (
        IThreatActorRepository,
    )


class IUnitOfWork(ABC):
    threat_actors: IThreatActorRepository
    associations: IThreatActorAssociationRepository

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
