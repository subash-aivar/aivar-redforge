"""Canonical asset/service enrichment for bounded network discovery — M12.

Mirrors `application/network_discovery/service.TenantNetworkDiscoveryService.
run_discovery()` (M6) exactly: resolves canonical IP_ADDRESS/HOST/SERVICE
`AIAsset`s via `TenantAssetService.resolve_asset()` (race-safe,
idempotent — repeated discovery never duplicates a canonical identity)
and links them via the same M6 `AssetRelationshipType` values, so M9's
existing `PUBLIC_SENSITIVE_SERVICE_CONTEXT` correlation rule recognizes
the resulting facts with zero changes to M9 itself.

Deliberately reuses `IdentityScheme.DISCOVERY_HOST`'s
`"{connector_id}:{hostname}"` shape with the AITarget's own id as the
scoping token (M12 has no "connector" concept — a gated
ValidationExecution against one canonical target is the scoping context
here, playing the identical structural role a connector plays for M6's
passive discovery).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import (
    AssetDiscoverySource,
    AssetRelationshipType,
    AssetType,
)

if TYPE_CHECKING:
    from redforge.application.inventory.tenant_asset_service import TenantAssetService


@dataclass(frozen=True, slots=True)
class ServiceAssetRef:
    port: int
    service_asset_id: str
    host_asset_id: str


@dataclass(frozen=True, slots=True)
class EnrichmentResult:
    ip_asset_ids: tuple[str, ...]
    host_asset_id: str | None
    services: tuple[ServiceAssetRef, ...]


async def enrich_discovered_assets(
    asset_service: TenantAssetService,
    organization_id: str,
    target_id: str,
    target_asset_id: str,
    resolved_addresses: tuple[str, ...],
    reachable_ports: tuple[int, ...],
) -> EnrichmentResult:
    """Resolves/links canonical IP_ADDRESS -> HOST -> SERVICE assets for
    one target's discovered addresses/ports. Never duplicates a
    canonical identity on repeated discovery (`resolve_asset` is a
    race-safe get-or-create); never invents identity for a port with no
    real observation."""
    ip_asset_ids: list[str] = []
    host_asset_id: str | None = None
    services: list[ServiceAssetRef] = []

    for ip in resolved_addresses:
        ip_asset = await asset_service.resolve_asset(
            organization_id=organization_id,
            asset_type=AssetType.IP_ADDRESS,
            scheme=IdentityScheme.IP_ADDRESS,
            raw_external_id=ip,
            name=ip,
            description=f"Resolved IP address for validation target {target_id}",
            discovery_source=AssetDiscoverySource.VALIDATION_DISCOVERY,
        )
        ip_asset_ids.append(ip_asset.id)

        await asset_service.add_relationship_for_org(
            organization_id, target_asset_id, ip_asset.id,
            AssetRelationshipType.TARGET_RESOLVES_TO_IP,
        )

        if reachable_ports and host_asset_id is None:
            host_asset = await asset_service.resolve_asset(
                organization_id=organization_id,
                asset_type=AssetType.HOST,
                scheme=IdentityScheme.DISCOVERY_HOST,
                raw_external_id=f"{target_id}:{ip}",
                name=ip,
                description=f"Discovered host for validation target {target_id}",
                discovery_source=AssetDiscoverySource.VALIDATION_DISCOVERY,
            )
            host_asset_id = host_asset.id
            await asset_service.add_relationship_for_org(
                organization_id, ip_asset.id, host_asset.id,
                AssetRelationshipType.IP_ASSIGNED_TO_HOST,
            )

    if host_asset_id is not None:
        for port in reachable_ports:
            service_asset = await asset_service.resolve_asset(
                organization_id=organization_id,
                asset_type=AssetType.SERVICE,
                scheme=IdentityScheme.SERVICE_ENDPOINT,
                raw_external_id=f"{host_asset_id}:tcp:{port}",
                name=f"tcp/{port} on {host_asset_id}",
                description=f"Discovered tcp/{port} service for validation target {target_id}",
                discovery_source=AssetDiscoverySource.VALIDATION_DISCOVERY,
            )
            await asset_service.add_relationship_for_org(
                organization_id, host_asset_id, service_asset.id,
                AssetRelationshipType.HOST_EXPOSES_SERVICE,
            )
            services.append(
                ServiceAssetRef(
                    port=port, service_asset_id=service_asset.id, host_asset_id=host_asset_id,
                )
            )

    return EnrichmentResult(
        ip_asset_ids=tuple(ip_asset_ids), host_asset_id=host_asset_id,
        services=tuple(services),
    )
