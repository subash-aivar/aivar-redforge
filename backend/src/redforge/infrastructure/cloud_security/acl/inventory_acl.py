"""CloudAsset → M22 inventory projection ACL (reuses TenantAssetService)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import (
    AssetDiscoverySource,
    AssetRelationshipType,
    AssetType,
)

if TYPE_CHECKING:
    from redforge.application.inventory.tenant_asset_service import TenantAssetService
    from redforge.domain.cloud_security.cloud_account import CloudAccount
    from redforge.domain.cloud_security.cloud_asset import CloudAsset
    from redforge.domain.cloud_security.cloud_provider import CloudProvider


def _resource_description(asset: CloudAsset, provider: CloudProvider) -> str:
    return (
        f"provider={provider.provider_type.value};"
        f"cloud_asset_type={asset.asset_type.value};"
        f"region={asset.region.region_code};"
        f"cloud_asset_id={asset.id}"
    )


class CloudAssetToInventoryACL:
    """Projects CloudAsset aggregates into M22 AIAsset inventory records.

    Uses the same resolve_asset path as M7 TenantCloudSecurityService:
    CLOUD_ACCOUNT + CLOUD_RESOURCE with CLOUD_ACCOUNT_CONTAINS_RESOURCE.
    """

    def __init__(self, asset_service: TenantAssetService) -> None:
        self._asset_service = asset_service

    async def project_asset(
        self,
        *,
        asset: CloudAsset,
        account: CloudAccount,
        provider: CloudProvider,
    ) -> None:
        if asset.is_deleted:
            return
        organization_id = str(asset.organization_id)
        provider_key = provider.provider_type.value.lower()
        account_asset = await self._asset_service.resolve_asset(
            organization_id=organization_id,
            asset_type=AssetType.CLOUD_ACCOUNT,
            scheme=IdentityScheme.CLOUD_ACCOUNT_ID,
            raw_external_id=f"{provider_key}:{account.external_id}",
            name=account.display_name,
            description=f"provider={provider.provider_type.value}",
            discovery_source=AssetDiscoverySource.API_SCAN,
        )
        resource_asset = await self._asset_service.resolve_asset(
            organization_id=organization_id,
            asset_type=AssetType.CLOUD_RESOURCE,
            scheme=IdentityScheme.CLOUD_RESOURCE_ID,
            raw_external_id=asset.provider_id,
            name=asset.display_name,
            description=_resource_description(asset, provider),
            discovery_source=AssetDiscoverySource.API_SCAN,
            metadata_entries={
                "cloud_asset_id": str(asset.id),
                "cloud_asset_type": asset.asset_type.value,
                "cloud_account_id": str(account.id),
            },
        )
        await self._asset_service.add_relationship_for_org(
            organization_id,
            account_asset.id,
            resource_asset.id,
            AssetRelationshipType.CLOUD_ACCOUNT_CONTAINS_RESOURCE,
        )
