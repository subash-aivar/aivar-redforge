"""AssetInventoryRecord — the read-only projection of a `CloudAsset`
the inventory hands back to every caller (M45B). Never mutated;
rebuilt fresh from the aggregate each time."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from cloud_security.domain.value_objects.cloud_tag import CloudTagSet
    from cloud_security.domain.value_objects.enums import (
        CloudAssetLifecycleState,
        CloudAssetType,
        CloudRiskLevel,
    )


@dataclass(frozen=True, slots=True)
class AssetInventoryRecord:
    asset_id: str
    tenant_id: str
    account_id: str
    asset_type: CloudAssetType
    native_id: str
    region_id: str | None
    tags: CloudTagSet
    risk_level: CloudRiskLevel
    lifecycle_state: CloudAssetLifecycleState
    discovered_at: datetime
    updated_at: datetime
