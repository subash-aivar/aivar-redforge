"""Commands, queries, and DTOs for M26 Phase 2 asset discovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True, slots=True)
class TriggerAssetDiscoveryCommand:
    organization_id: str
    cloud_account_id: str
    asset_types: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ListCloudAssetsQuery:
    organization_id: str
    page: int = 1
    size: int = 50
    cloud_account_id: str | None = None
    asset_type: str | None = None
    include_deleted: bool = False


@dataclass(frozen=True, slots=True)
class GetCloudAssetQuery:
    organization_id: str
    asset_id: str


@dataclass(frozen=True, slots=True)
class ListAssetRelationshipsQuery:
    organization_id: str
    asset_id: str


@dataclass(frozen=True, slots=True)
class DiscoveryResultDTO:
    cloud_account_id: str
    organization_id: str
    sync_status: str
    discovered_count: int
    updated_count: int
    resurrected_count: int
    deleted_count: int
    projected_count: int
    errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AssetRelationshipDTO:
    relationship_id: str
    relationship_type: str
    target_provider_id: str
    target_asset_id: str | None


@dataclass(frozen=True, slots=True)
class CloudAssetDTO:
    asset_id: str
    cloud_account_id: str
    organization_id: str
    asset_type: str
    provider_id: str
    display_name: str
    region_code: str
    az_name: str | None
    tags: dict[str, str]
    config_hash: str
    is_deleted: bool
    last_seen_at: datetime
    first_seen_at: datetime
    created_at: datetime
    updated_at: datetime
    version: int
    relationships: list[AssetRelationshipDTO] = field(default_factory=list)
    normalized_config: dict[str, object] = field(default_factory=dict)
    provider_metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CloudAssetPageDTO:
    items: list[CloudAssetDTO]
    page: int
    size: int
    total: int
