"""CloudAssetDto — the read-only projection of a `CloudAsset` returned
by the application layer (M45A)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from cloud_security.domain.value_objects.enums import CloudAssetType, CloudRiskLevel


@dataclass(frozen=True, slots=True)
class CloudAssetDto:
    asset_id: str
    tenant_id: str
    account_id: str
    asset_type: CloudAssetType
    native_id: str
    risk_level: CloudRiskLevel
    discovered_at: datetime
    updated_at: datetime
