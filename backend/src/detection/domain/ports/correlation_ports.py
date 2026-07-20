"""ACL outbound ports for detection correlation — normalized snapshots only."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from detection.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class AssetMetadataSnapshot:
    asset_id: str
    asset_type: str = "unknown"
    business_criticality: float = 0.5
    tags: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CloudContextSnapshot:
    asset_id: str
    internet_exposed: bool = False
    publicly_reachable: bool = False
    cloud_provider: str | None = None
    region: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class BehavioralSignalSnapshot:
    asset_id: str
    anomaly_score: float = 0.0
    signals: dict[str, Any] = field(default_factory=dict)


class IInventoryAdapter(ABC):
    """ACL to Inventory (M22)."""

    @abstractmethod
    async def resolve_asset(
        self, asset_id: str, tenant_id: TenantId
    ) -> AssetMetadataSnapshot: ...


class ICloudContextAdapter(ABC):
    """ACL to Cloud context (M26)."""

    @abstractmethod
    async def resolve_cloud(
        self, asset_id: str, tenant_id: TenantId
    ) -> CloudContextSnapshot: ...


class IVulnerabilityContextAdapter(ABC):
    """ACL to Vulnerability (M27) — returns instance ref strings only."""

    @abstractmethod
    async def resolve_vulnerabilities(
        self, asset_id: str, tenant_id: TenantId
    ) -> list[str]: ...


class IThreatIntelAdapter(ABC):
    """ACL to Threat Intelligence (M20)."""

    @abstractmethod
    async def resolve_threat_actors(
        self,
        *,
        asset_id: str,
        rule_id: str,
        tenant_id: TenantId,
    ) -> list[str]: ...


class IComplianceAdapter(ABC):
    """ACL to Compliance (M24)."""

    @abstractmethod
    async def resolve_controls(
        self, rule_id: str, tenant_id: TenantId
    ) -> list[str]: ...


class IBehavioralSignalAdapter(ABC):
    """ACL to Behavioral / UEBA signals (M20)."""

    @abstractmethod
    async def resolve_behavioral(
        self, asset_id: str, tenant_id: TenantId
    ) -> BehavioralSignalSnapshot: ...


# Freeze-facing aliases
InventoryAdapter = IInventoryAdapter
CloudContextAdapter = ICloudContextAdapter
VulnerabilityContextAdapter = IVulnerabilityContextAdapter
ThreatIntelAdapter = IThreatIntelAdapter
ComplianceAdapter = IComplianceAdapter
BehavioralSignalAdapter = IBehavioralSignalAdapter
