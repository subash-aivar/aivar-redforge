"""Degraded ACL adapters — safe defaults when upstream is unavailable.

Intentionally do NOT call Inventory/Cloud/Intel/Compliance implementations.
Real adapters are deferred; Phase 4 requires ports + degradable implementations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from detection.domain.ports.correlation_ports import (
    AssetMetadataSnapshot,
    BehavioralSignalSnapshot,
    CloudContextSnapshot,
    IBehavioralSignalAdapter,
    ICloudContextAdapter,
    IComplianceAdapter,
    IInventoryAdapter,
    IThreatIntelAdapter,
    IVulnerabilityContextAdapter,
)

if TYPE_CHECKING:
    from detection.domain.value_objects.identifiers import TenantId


class InventoryAdapter(IInventoryAdapter):
    async def resolve_asset(
        self, asset_id: str, tenant_id: TenantId
    ) -> AssetMetadataSnapshot:
        _ = tenant_id
        return AssetMetadataSnapshot(asset_id=asset_id, asset_type="unknown")


class CloudContextAdapter(ICloudContextAdapter):
    async def resolve_cloud(
        self, asset_id: str, tenant_id: TenantId
    ) -> CloudContextSnapshot:
        _ = tenant_id
        return CloudContextSnapshot(asset_id=asset_id)


class VulnerabilityContextAdapter(IVulnerabilityContextAdapter):
    async def resolve_vulnerabilities(
        self, asset_id: str, tenant_id: TenantId
    ) -> list[str]:
        _ = asset_id, tenant_id
        return []


class ThreatIntelAdapter(IThreatIntelAdapter):
    async def resolve_threat_actors(
        self,
        *,
        asset_id: str,
        rule_id: str,
        tenant_id: TenantId,
    ) -> list[str]:
        _ = asset_id, rule_id, tenant_id
        return []


class ComplianceAdapter(IComplianceAdapter):
    async def resolve_controls(
        self, rule_id: str, tenant_id: TenantId
    ) -> list[str]:
        _ = rule_id, tenant_id
        return []


class BehavioralSignalAdapter(IBehavioralSignalAdapter):
    async def resolve_behavioral(
        self, asset_id: str, tenant_id: TenantId
    ) -> BehavioralSignalSnapshot:
        _ = tenant_id
        return BehavioralSignalSnapshot(asset_id=asset_id)
