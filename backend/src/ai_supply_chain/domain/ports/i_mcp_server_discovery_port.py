from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_supply_chain.domain.value_objects.identifiers import TenantId
    from ai_supply_chain.domain.value_objects.supply_chain_vos import DiscoveredAIService


class IMCPServerDiscoveryPort(ABC):
    """Thin versioned adapter — MCP protocol details stay in infrastructure."""

    @abstractmethod
    async def list_mcp_servers(self, tenant_id: TenantId) -> list[DiscoveredAIService]: ...
