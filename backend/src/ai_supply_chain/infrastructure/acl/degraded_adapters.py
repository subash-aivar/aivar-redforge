"""ACL adapters — never import foreign domain types."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_supply_chain.domain.ports.i_inventory_match_port import IInventoryMatchPort
from ai_supply_chain.domain.ports.i_shadow_alert_raise_port import IShadowAlertRaisePort
from ai_supply_chain.domain.ports.i_vulnerability_query_port import IVulnerabilityQueryPort

if TYPE_CHECKING:
    from ai_supply_chain.domain.value_objects.identifiers import TenantId
    from ai_supply_chain.domain.value_objects.supply_chain_vos import DiscoveredAIService


class StubVulnerabilityQueryAdapter(IVulnerabilityQueryPort):
    def __init__(self) -> None:
        self.cves: dict[tuple[str, str], list[str]] = {}

    async def find_cves_for_component(
        self, tenant_id: TenantId, name: str, version: str
    ) -> list[str]:
        return list(self.cves.get((name, version), []))


class RecordingInventoryMatchAdapter(IInventoryMatchPort):
    def __init__(self) -> None:
        self.known_resources: set[str] = set()

    async def has_matching_asset(self, tenant_id: TenantId, service: DiscoveredAIService) -> bool:
        return service.resource_identifier in self.known_resources


class RecordingShadowAlertRaiseAdapter(IShadowAlertRaisePort):
    def __init__(self) -> None:
        self.raised: list[DiscoveredAIService] = []

    async def raise_for_unmatched(self, tenant_id: TenantId, service: DiscoveredAIService) -> None:
        self.raised.append(service)
