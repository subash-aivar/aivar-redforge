from __future__ import annotations

from dataclasses import dataclass

from integration_hub.domain.events.base import BaseConnectorEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class AssetDiscovered(BaseConnectorEvent):
    asset_id: str
    connector_id: str
    vendor: str
    category: str
    external_id: str
    discovered_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AssetModified(BaseConnectorEvent):
    asset_id: str
    connector_id: str
    change_type: str
    modified_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AssetRemoved(BaseConnectorEvent):
    asset_id: str
    connector_id: str
    removed_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AssetDriftDetected(BaseConnectorEvent):
    asset_id: str
    connector_id: str
    change_type: str
    detail: str | None
    detected_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AssetRelationshipAdded(BaseConnectorEvent):
    asset_id: str
    relationship_type: str
    target_external_id: str
    added_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AssetRelationshipRemoved(BaseConnectorEvent):
    asset_id: str
    relationship_type: str
    target_external_id: str
    removed_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SyncRunCompleted(BaseConnectorEvent):
    sync_run_id: str
    connector_id: str
    items_discovered: int
    items_created: int
    items_updated: int
    items_deleted: int
    completed_at: str
