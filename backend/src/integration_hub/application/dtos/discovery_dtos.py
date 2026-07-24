from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class AssetRelationshipDTO:
    relationship_type: str
    target_external_id: str
    target_asset_id: str | None


@dataclass(frozen=True, slots=True)
class DiscoveredAssetDTO:
    asset_id: str
    tenant_id: str
    connector_id: str
    external_id: str
    name: str
    category: str
    vendor: str
    region: str | None
    owner: str | None
    security_state: str
    compliance_state: str
    health_status: str | None
    risk_score: int
    tags: dict[str, str]
    metadata: dict[str, object]
    relationships: list[AssetRelationshipDTO] = field(default_factory=list)
    discovered_at: str = ""
    last_synced_at: str = ""


@dataclass(frozen=True, slots=True)
class SyncRunDTO:
    sync_run_id: str
    connector_id: str
    mode: str
    status: str
    started_at: str
    completed_at: str | None
    items_discovered: int
    items_created: int
    items_updated: int
    items_deleted: int
    error: str | None
    cursor: str | None = None
    pages_processed: int = 0
    has_more: bool = False
