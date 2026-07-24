"""IAssetWriter — the write-side extension point for the Asset
Inventory (M45B). No concrete implementation exists in this
milestone — the application service operates directly on the
`CloudAsset` aggregate it is handed; this port exists for a future
infrastructure milestone to persist the resulting record, not for
this milestone to call."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from cloud_security.application.dtos.asset_inventory_record import AssetInventoryRecord
    from cloud_security.domain.value_objects.identifiers import AssetId, TenantId


class IAssetWriter(Protocol):
    def save(self, record: AssetInventoryRecord) -> None: ...

    def delete(self, tenant_id: TenantId, asset_id: AssetId) -> None: ...
