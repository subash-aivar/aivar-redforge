from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_supply_chain.domain.value_objects.identifiers import TenantId
    from ai_supply_chain.domain.value_objects.supply_chain_vos import DiscoveredAIService


class IShadowAlertRaisePort(ABC):
    """Outbound port — raise ShadowAIAlert in ai_posture without importing its domain."""

    @abstractmethod
    async def raise_for_unmatched(
        self, tenant_id: TenantId, service: DiscoveredAIService
    ) -> None: ...
