"""IUnitOfWork — mirrors `malware_intel.application.ports.i_unit_of_work.
IUnitOfWork`'s shape exactly."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from campaign_intel.application.ports.i_campaign_repository import ICampaignRepository


class IUnitOfWork(ABC):
    campaigns: ICampaignRepository

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
