from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_supply_chain.domain.value_objects.identifiers import TenantId
    from ai_supply_chain.domain.value_objects.supply_chain_vos import DiscoveredAIService


class IInventoryMatchPort(ABC):
    """ACL to M22/ai_posture — whether a discovered service already has an asset."""

    @abstractmethod
    async def has_matching_asset(
        self, tenant_id: TenantId, service: DiscoveredAIService
    ) -> bool: ...
