"""AssetFactory — the only supported way to construct an `Asset`.
Requires at least one network identifier (domain, subdomain, or IP
address); the aggregate's own `__init__` also enforces this (defense in
depth, matching `EnterpriseRiskProfile`/`RiskProfileFactory`'s split of
"who is allowed to construct" vs "what must be true to exist")."""

from __future__ import annotations

from typing import TYPE_CHECKING

from attack_surface_management.domain.aggregates.asset import Asset
from attack_surface_management.domain.value_objects.enums import AssetType, DiscoverySource
from attack_surface_management.domain.value_objects.identifiers import AssetId

if TYPE_CHECKING:
    from datetime import datetime

    from attack_surface_management.domain.value_objects.domain_name import DomainName, Subdomain
    from attack_surface_management.domain.value_objects.identifiers import TenantId
    from attack_surface_management.domain.value_objects.ip_address import IPAddress


class AssetFactory:
    @staticmethod
    def discover(
        tenant_id: TenantId,
        asset_type: AssetType,
        now: datetime,
        domain_name: DomainName | None = None,
        subdomain: Subdomain | None = None,
        ip_address: IPAddress | None = None,
        discovery_source: DiscoverySource = DiscoverySource.MANUAL_ENTRY,
        asset_id: AssetId | None = None,
    ) -> Asset:
        resolved_id = asset_id or AssetId.generate()
        return Asset._create(
            asset_id=resolved_id,
            tenant_id=tenant_id,
            asset_type=asset_type,
            now=now,
            domain_name=domain_name,
            subdomain=subdomain,
            ip_address=ip_address,
            discovery_source=discovery_source,
        )
