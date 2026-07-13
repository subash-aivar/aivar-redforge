"""Domain events for the Enterprise AI Asset & Inventory bounded context."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _make_event_id() -> str:
    from ulid import ULID
    return str(ULID())


@dataclass(frozen=True, slots=True)
class InventoryDomainEvent:
    """Base for all inventory domain events."""

    organization_id: str
    asset_id: str
    event_id: str = field(default_factory=_make_event_id)
    occurred_at_iso: str = field(default_factory=_now_iso)


@dataclass(frozen=True, slots=True)
class AssetRegistered(InventoryDomainEvent):
    asset_type: str = ""
    name: str = ""
    discovery_source: str = ""
    fingerprint_hash: str = ""


@dataclass(frozen=True, slots=True)
class AssetDiscovered(InventoryDomainEvent):
    asset_type: str = ""
    discovery_source: str = ""
    external_id: str = ""


@dataclass(frozen=True, slots=True)
class AssetFingerprintChanged(InventoryDomainEvent):
    old_fingerprint_hash: str = ""
    new_fingerprint_hash: str = ""
    version_tag: str = ""


@dataclass(frozen=True, slots=True)
class AssetLifecycleChanged(InventoryDomainEvent):
    from_stage: str = ""
    to_stage: str = ""


@dataclass(frozen=True, slots=True)
class AssetOwnerChanged(InventoryDomainEvent):
    old_owner_id: str | None = None
    new_owner_id: str = ""


@dataclass(frozen=True, slots=True)
class AssetHealthUpdated(InventoryDomainEvent):
    old_health: str = ""
    new_health: str = ""


@dataclass(frozen=True, slots=True)
class AssetRelationshipAdded(InventoryDomainEvent):
    relationship_id: str = ""
    target_asset_id: str = ""
    relationship_type: str = ""


@dataclass(frozen=True, slots=True)
class AssetRelationshipRemoved(InventoryDomainEvent):
    relationship_id: str = ""
    target_asset_id: str = ""


@dataclass(frozen=True, slots=True)
class AssetDependencyAdded(InventoryDomainEvent):
    dependency_id: str = ""
    relationship_type: str = ""
    is_required: bool = True


@dataclass(frozen=True, slots=True)
class AssetDependencyRemoved(InventoryDomainEvent):
    dependency_id: str = ""


@dataclass(frozen=True, slots=True)
class InventorySnapshotCreated(InventoryDomainEvent):
    snapshot_id: str = ""
    asset_count: int = 0
    new_asset_count: int = 0
    changed_asset_count: int = 0
    retired_asset_count: int = 0
