"""Domain events produced by the `CloudAsset` aggregate (M45A, extended
M45B with the inventory's move/decommission lifecycle)."""

from __future__ import annotations

from dataclasses import dataclass

from cloud_security.domain.events.base import BaseDomainEvent
from cloud_security.domain.value_objects.enums import CloudAssetType


@dataclass(frozen=True, slots=True)
class AssetDiscovered(BaseDomainEvent):
    asset_type: CloudAssetType = CloudAssetType.OTHER
    account_id: str = ""


@dataclass(frozen=True, slots=True)
class AssetUpdated(BaseDomainEvent):
    updated_fields: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AssetMoved(BaseDomainEvent):
    from_account_id: str = ""
    to_account_id: str = ""
    from_region: str = ""
    to_region: str = ""


@dataclass(frozen=True, slots=True)
class AssetDecommissioned(BaseDomainEvent):
    pass
