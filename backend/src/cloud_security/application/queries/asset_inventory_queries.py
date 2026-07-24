"""Immutable CQRS query objects for the Cloud Asset Inventory (M45B).

Every query names `platform_type` — the same registry key
`IAssetInventoryRegistry` resolves an `IAssetInventoryProvider` by
(mirrors `SearchQuery`/`AnalyticsQuery`'s registry-key pattern from
M44E/M44F)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cloud_security.domain.value_objects.enums import CloudAssetType, CloudPlatformType
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        AssetId,
        RegionId,
        TenantId,
    )


@dataclass(frozen=True, slots=True)
class GetAssetQuery:
    tenant_id: TenantId
    platform_type: CloudPlatformType
    asset_id: AssetId


@dataclass(frozen=True, slots=True)
class ListAssetsQuery:
    tenant_id: TenantId
    platform_type: CloudPlatformType
    account_id: AccountId | None = None


@dataclass(frozen=True, slots=True)
class ListAssetsByTypeQuery:
    tenant_id: TenantId
    platform_type: CloudPlatformType
    asset_type: CloudAssetType


@dataclass(frozen=True, slots=True)
class ListAssetsByRegionQuery:
    tenant_id: TenantId
    platform_type: CloudPlatformType
    region_id: RegionId


@dataclass(frozen=True, slots=True)
class ListAssetsByProviderQuery:
    tenant_id: TenantId
    platform_type: CloudPlatformType


@dataclass(frozen=True, slots=True)
class SearchAssetsQuery:
    tenant_id: TenantId
    platform_type: CloudPlatformType
    filters: Mapping[str, object] = field(default_factory=dict)
