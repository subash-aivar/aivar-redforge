"""CloudAssetApplicationService — application-layer orchestration for
`CloudAsset` commands (M45A). Scaffolding only — see
`cloud_account_application_service` for the "no persistence in this
milestone" rationale, which applies identically here."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from cloud_security.application.dtos.cloud_asset_dto import CloudAssetDto
from cloud_security.domain.aggregates.cloud_asset import CloudAsset
from cloud_security.domain.value_objects.enums import CloudRiskLevel
from cloud_security.domain.value_objects.identifiers import AssetId

if TYPE_CHECKING:
    from cloud_security.application.commands.cloud_asset_commands import (
        DiscoverCloudAssetCommand,
        UpdateCloudAssetCommand,
    )


def _to_dto(asset: CloudAsset) -> CloudAssetDto:
    return CloudAssetDto(
        asset_id=str(asset.asset_id),
        tenant_id=str(asset.tenant_id),
        account_id=str(asset.account_id),
        asset_type=asset.resource.asset_type,
        native_id=asset.resource.native_id,
        risk_level=asset.risk_level,
        discovered_at=asset.discovered_at,
        updated_at=asset.updated_at,
    )


class CloudAssetApplicationService:
    def discover_asset(self, cmd: DiscoverCloudAssetCommand) -> CloudAssetDto:
        asset = CloudAsset.discover(
            asset_id=AssetId.generate(),
            tenant_id=cmd.tenant_id,
            account_id=cmd.account_id,
            resource=cmd.resource,
            tags=cmd.tags,
            risk_level=CloudRiskLevel.LOW,
            metadata=cmd.metadata,
            now=datetime.now(UTC),
        )
        return _to_dto(asset)

    def update_asset(self, asset: CloudAsset, cmd: UpdateCloudAssetCommand) -> CloudAssetDto:
        asset.update(
            tenant_id=cmd.tenant_id,
            now=datetime.now(UTC),
            tags=cmd.tags,
            risk_level=cmd.risk_level,
            metadata=cmd.metadata,
        )
        return _to_dto(asset)
