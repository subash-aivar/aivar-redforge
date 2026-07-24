"""IAssetReader — the read-side extension point for the Asset
Inventory (M45B). No concrete implementation exists in this
milestone — a future infrastructure milestone backs this with real
storage; this milestone only defines the shape."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from cloud_security.application.dtos.asset_inventory_record import AssetInventoryRecord
    from cloud_security.domain.value_objects.enums import CloudAssetType
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        AssetId,
        RegionId,
        TenantId,
    )


class IAssetReader(Protocol):
    def get(self, tenant_id: TenantId, asset_id: AssetId) -> AssetInventoryRecord | None: ...

    def list(
        self,
        tenant_id: TenantId,
        account_id: AccountId | None = None,
        asset_type: CloudAssetType | None = None,
        region_id: RegionId | None = None,
    ) -> Sequence[AssetInventoryRecord]: ...

    def search(
        self, tenant_id: TenantId, filters: Mapping[str, object]
    ) -> Sequence[AssetInventoryRecord]: ...
