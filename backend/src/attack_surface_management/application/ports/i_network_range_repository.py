"""INetworkRangeRepository — an async ABC port for tenant-scoped
persistence of `NetworkRange` aggregates, matching `IAssetRepository`'s
shape exactly."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from attack_surface_management.domain.aggregates.network_range import NetworkRange
    from attack_surface_management.domain.value_objects.identifiers import (
        NetworkRangeId,
        TenantId,
    )


class INetworkRangeRepository(ABC):
    @abstractmethod
    async def save(self, network_range: NetworkRange) -> None: ...

    @abstractmethod
    async def get(self, tenant_id: TenantId, range_id: NetworkRangeId) -> NetworkRange | None: ...

    @abstractmethod
    async def list(self, tenant_id: TenantId, **filters: object) -> Sequence[NetworkRange]: ...
