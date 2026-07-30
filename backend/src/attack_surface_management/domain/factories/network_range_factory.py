"""NetworkRangeFactory — the only supported way to construct a
`NetworkRange`."""

from __future__ import annotations

from typing import TYPE_CHECKING

from attack_surface_management.domain.aggregates.network_range import NetworkRange
from attack_surface_management.domain.value_objects.enums import DiscoverySource
from attack_surface_management.domain.value_objects.identifiers import NetworkRangeId

if TYPE_CHECKING:
    from datetime import datetime

    from attack_surface_management.domain.value_objects.cidr_block import CidrBlock
    from attack_surface_management.domain.value_objects.identifiers import TenantId


class NetworkRangeFactory:
    @staticmethod
    def discover(
        tenant_id: TenantId,
        cidr: CidrBlock,
        now: datetime,
        discovery_source: DiscoverySource = DiscoverySource.MANUAL_ENTRY,
        range_id: NetworkRangeId | None = None,
    ) -> NetworkRange:
        resolved_id = range_id or NetworkRangeId.generate()
        return NetworkRange._create(
            range_id=resolved_id,
            tenant_id=tenant_id,
            cidr=cidr,
            now=now,
            discovery_source=discovery_source,
        )
