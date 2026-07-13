"""TenantNetworkDiscoveryService — M6.

Orchestrates: BOUNDED SCAN ADAPTER -> TYPED OBSERVATIONS -> canonical
NETWORK/IP_ADDRESS/HOST/SERVICE asset resolution (reusing the M3
`AIAsset` aggregate and `TenantAssetService`, not a disconnected
network inventory) -> canonical relationship persistence -> best-effort
Security Graph projection (already wired into `TenantAssetService`) ->
deterministic network exposure analysis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.application.network_discovery.analysis_service import (
    NetworkSecurityObservation,
    analyze,
)
from redforge.application.network_discovery.observations import NetworkDiscoveryResult
from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import (
    AssetDiscoverySource,
    AssetRelationshipType,
    AssetType,
)

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from redforge.application.inventory.tenant_asset_service import TenantAssetService
    from redforge.application.security_conditions.service import TenantSecurityConditionService

# Deterministic, backend-derived severity per rule ID — never a raw
# CVSS vector (no producing source has one). Any rule_id not listed
# here is intentionally not ingested as a SecurityCondition (still
# returned as a live observation) rather than fabricating a severity.
_RULE_SEVERITY: dict[str, str] = {
    "PUBLICLY_ADDRESSABLE_ASSET": "informational",
    "SENSITIVE_SERVICE_OBSERVED": "medium",
    "MULTIPLE_REMOTE_ADMIN_SERVICES": "high",
}


@dataclass(frozen=True, slots=True)
class NetworkDiscoverySummary:
    ips_observed: int
    hosts_observed: int
    services_observed: int
    errors: tuple[str, ...]


class TenantNetworkDiscoveryService:
    def __init__(
        self,
        asset_service: TenantAssetService,
        condition_service: TenantSecurityConditionService | None = None,
    ) -> None:
        self._asset_service = asset_service
        self._condition_service = condition_service

    async def run_discovery(
        self, organization_id: str, connector_id: str, result: NetworkDiscoveryResult
    ) -> NetworkDiscoverySummary:
        asset_service = self._asset_service

        network_asset = await asset_service.resolve_asset(
            organization_id=organization_id,
            asset_type=AssetType.NETWORK,
            scheme=IdentityScheme.NETWORK_CIDR,
            raw_external_id=result.network_cidr,
            name=result.network_cidr,
            description=f"Discovered network range {result.network_cidr}",
            discovery_source=AssetDiscoverySource.API_SCAN,
        )

        hostname_by_ip = {h.ip: h.hostname for h in result.hosts}
        ip_asset_id_by_ip: dict[str, str] = {}
        host_asset_id_by_ip: dict[str, str] = {}

        for ip_obs in result.ip_addresses:
            ip_asset = await asset_service.resolve_asset(
                organization_id=organization_id,
                asset_type=AssetType.IP_ADDRESS,
                scheme=IdentityScheme.IP_ADDRESS,
                raw_external_id=ip_obs.ip,
                name=ip_obs.ip,
                description=f"Discovered IP address {ip_obs.ip}",
                discovery_source=AssetDiscoverySource.API_SCAN,
            )
            ip_asset_id_by_ip[ip_obs.ip] = ip_asset.id

            hostname = hostname_by_ip.get(ip_obs.ip, ip_obs.ip)
            host_asset = await asset_service.resolve_asset(
                organization_id=organization_id,
                asset_type=AssetType.HOST,
                scheme=IdentityScheme.DISCOVERY_HOST,
                raw_external_id=f"{connector_id}:{hostname}",
                name=hostname,
                description=f"Discovered host at {ip_obs.ip}",
                discovery_source=AssetDiscoverySource.API_SCAN,
            )
            host_asset_id_by_ip[ip_obs.ip] = host_asset.id

            await asset_service.add_relationship_for_org(
                organization_id, ip_asset.id, host_asset.id,
                AssetRelationshipType.IP_ASSIGNED_TO_HOST,
            )
            await asset_service.add_relationship_for_org(
                organization_id, ip_asset.id, network_asset.id,
                AssetRelationshipType.IP_MEMBER_OF_NETWORK,
            )

        for svc in result.services:
            host_asset_id = host_asset_id_by_ip.get(svc.host_ip)
            if host_asset_id is None:
                continue
            service_name = svc.safe_service_name or f"port-{svc.port}"
            service_asset = await asset_service.resolve_asset(
                organization_id=organization_id,
                asset_type=AssetType.SERVICE,
                scheme=IdentityScheme.SERVICE_ENDPOINT,
                raw_external_id=f"{host_asset_id}:{svc.protocol}:{svc.port}",
                name=f"{service_name} ({svc.protocol}/{svc.port}) on {svc.host_ip}",
                description=f"Discovered {svc.protocol}/{svc.port} service",
                discovery_source=AssetDiscoverySource.API_SCAN,
            )
            await asset_service.add_relationship_for_org(
                organization_id, host_asset_id, service_asset.id,
                AssetRelationshipType.HOST_EXPOSES_SERVICE,
            )

        return NetworkDiscoverySummary(
            ips_observed=len(result.ip_addresses),
            hosts_observed=len(result.hosts),
            services_observed=len(result.services),
            errors=result.errors,
        )

    async def list_exposure_observations(
        self, organization_id: str
    ) -> list[NetworkSecurityObservation]:
        asset_service = self._asset_service
        assets: list[dict[str, str]] = []
        for asset_type in ("ip_address", "service"):
            rows = await asset_service.list_for_org(
                organization_id, asset_type=asset_type, limit=200
            )
            assets.extend(
                {
                    "id": r.id, "asset_type": r.asset_type,
                    "external_id": r.external_id, "name": r.name,
                }
                for r in rows
            )
        observations = analyze(assets)
        await self._ingest_conditions_best_effort(organization_id, observations)
        return observations

    async def _ingest_conditions_best_effort(
        self, organization_id: str, observations: list[NetworkSecurityObservation]
    ) -> None:
        """Routes eligible deterministic observations through the M8
        SecurityCondition ingestion port. Best-effort: an ingestion
        failure for one observation never blocks serving the live
        read-time observation list to the caller."""
        if self._condition_service is None:
            return
        from redforge.application.security_conditions.ingestion import SecurityConditionInput

        for obs in observations:
            severity = _RULE_SEVERITY.get(obs.rule_id)
            if severity is None:
                continue
            try:
                await self._condition_service.ingest(
                    SecurityConditionInput(
                        organization_id=organization_id,
                        affected_asset_id=obs.affected_asset_id,
                        source_category="network_discovery",
                        stable_rule_id=obs.rule_id,
                        evidence_state="observed",
                        severity=severity,
                        title=obs.title,
                        summary=obs.summary,
                    )
                )
            except Exception:
                logger.warning(
                    "network_discovery: security condition ingestion failed for rule_id=%s "
                    "asset_id=%s", obs.rule_id, obs.affected_asset_id, exc_info=True,
                )
