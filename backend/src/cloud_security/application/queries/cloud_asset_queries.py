"""Immutable CQRS query objects for `CloudAsset` reads (M45A)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.enums import CloudAssetType
    from cloud_security.domain.value_objects.identifiers import AccountId, AssetId, TenantId


@dataclass(frozen=True, slots=True)
class GetCloudAssetQuery:
    tenant_id: TenantId
    asset_id: AssetId


@dataclass(frozen=True, slots=True)
class ListCloudAssetsQuery:
    tenant_id: TenantId
    account_id: AccountId | None = None
    asset_type: CloudAssetType | None = None
