"""Canonical fact-gathering helpers shared by M9 correlation rules and
the attack-surface read model.

Every helper here reads ONLY already-canonical, already-persisted data
(AIAsset relationships, SecurityCondition rows) — no display-name
matching, no free-text similarity, no fabricated relationship.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.application.inventory.tenant_asset_service import TenantAssetService

_IP_PREFIX = "ip_address:"
_SERVICE_PREFIX = "service_endpoint:"


def _decode_ip(external_id: str) -> str | None:
    return external_id[len(_IP_PREFIX):] if external_id.startswith(_IP_PREFIX) else None


def _decode_service_host(external_id: str) -> str | None:
    """Extracts the host_asset_id encoded in a SERVICE_ENDPOINT
    external_id (`"service_endpoint:{host_asset_id}:{protocol}:{port}"`)
    — mirrors `network_discovery.analysis_service._decode_service`."""
    if not external_id.startswith(_SERVICE_PREFIX):
        return None
    parts = external_id[len(_SERVICE_PREFIX):].split(":")
    return parts[0] if len(parts) == 3 else None


async def public_ip_asset_ids(asset_service: TenantAssetService, organization_id: str) -> set[str]:
    """Canonical IP_ADDRESS assets whose address is RFC-accurate
    globally routable (`ipaddress.is_global`) — the same classification
    M6's `PUBLICLY_ADDRESSABLE_ASSET` rule uses, never re-derived from a
    heuristic."""
    rows = await asset_service.list_for_org(organization_id, asset_type="ip_address", limit=500)
    public_ids: set[str] = set()
    for row in rows:
        ip_str = _decode_ip(row.external_id)
        if ip_str is None:
            continue
        try:
            if ipaddress.ip_address(ip_str).is_global:
                public_ids.add(row.id)
        except ValueError:
            continue
    return public_ids


async def public_host_asset_ids(
    asset_service: TenantAssetService, organization_id: str, public_ips: set[str]
) -> set[str]:
    """Canonical HOST asset IDs reachable from a public IP via the
    already-persisted `IP_ASSIGNED_TO_HOST` relationship — never a
    guess from naming or co-location."""
    host_ids: set[str] = set()
    for ip_id in public_ips:
        relationships = await asset_service.get_relationships_for_org(ip_id, organization_id)
        for rel in relationships:
            if rel["relationship_type"] == "ip_assigned_to_host":
                host_ids.add(rel["target_asset_id"])
    return host_ids


async def service_host_asset_id(
    asset_service: TenantAssetService, organization_id: str, service_asset_id: str
) -> str | None:
    """The canonical HOST asset ID a SERVICE asset belongs to, decoded
    from its own deterministic `SERVICE_ENDPOINT` identity — the same
    encoding `TenantNetworkDiscoveryService.run_discovery` writes, never
    re-derived from a relationship guess."""
    asset = await asset_service.get_for_org(service_asset_id, organization_id)
    return _decode_service_host(asset.external_id)
