"""Application wrapper for CloudAsset → M22 inventory projection."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.domain.cloud_security.cloud_account import CloudAccount
    from redforge.domain.cloud_security.cloud_asset import CloudAsset
    from redforge.domain.cloud_security.cloud_provider import CloudProvider
    from redforge.infrastructure.cloud_security.acl.inventory_acl import CloudAssetToInventoryACL


class InventoryProjectionService:
    """Projects non-deleted CloudAssets into the M22 inventory path."""

    def __init__(self, acl: CloudAssetToInventoryACL) -> None:
        self._acl = acl

    async def project(
        self,
        *,
        asset: CloudAsset,
        account: CloudAccount,
        provider: CloudProvider,
    ) -> None:
        await self._acl.project_asset(asset=asset, account=account, provider=provider)
