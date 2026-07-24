from __future__ import annotations

from datetime import UTC, datetime

from cloud_security.application.commands.cloud_asset_commands import (
    DiscoverCloudAssetCommand,
    UpdateCloudAssetCommand,
)
from cloud_security.application.services.cloud_asset_application_service import (
    CloudAssetApplicationService,
)
from cloud_security.domain.aggregates.cloud_asset import CloudAsset
from cloud_security.domain.value_objects.cloud_resource import CloudResource
from cloud_security.domain.value_objects.enums import CloudAssetType, CloudRiskLevel
from cloud_security.domain.value_objects.identifiers import (
    AccountId,
    AssetId,
    ResourceId,
    TenantId,
)


def _resource() -> CloudResource:
    return CloudResource(
        resource_id=ResourceId("res-1"),
        native_id="i-0123456789",
        asset_type=CloudAssetType.COMPUTE_INSTANCE,
    )


def test_discover_asset_returns_dto() -> None:
    service = CloudAssetApplicationService()
    cmd = DiscoverCloudAssetCommand(
        tenant_id=TenantId.generate(), account_id=AccountId.generate(), resource=_resource()
    )

    dto = service.discover_asset(cmd)

    assert dto.asset_type == CloudAssetType.COMPUTE_INSTANCE
    assert dto.native_id == "i-0123456789"
    assert dto.risk_level == CloudRiskLevel.LOW


def test_update_asset_returns_updated_dto() -> None:
    service = CloudAssetApplicationService()
    tenant_id = TenantId.generate()
    discover_cmd = DiscoverCloudAssetCommand(
        tenant_id=tenant_id, account_id=AccountId.generate(), resource=_resource()
    )
    service.discover_asset(discover_cmd)

    asset = CloudAsset.discover(
        asset_id=AssetId.generate(),
        tenant_id=tenant_id,
        account_id=discover_cmd.account_id,
        resource=discover_cmd.resource,
        tags=discover_cmd.tags,
        risk_level=CloudRiskLevel.LOW,
        metadata=discover_cmd.metadata,
        now=datetime.now(UTC),
    )

    dto = service.update_asset(
        asset, UpdateCloudAssetCommand(tenant_id=tenant_id, risk_level=CloudRiskLevel.CRITICAL)
    )

    assert dto.risk_level == CloudRiskLevel.CRITICAL
