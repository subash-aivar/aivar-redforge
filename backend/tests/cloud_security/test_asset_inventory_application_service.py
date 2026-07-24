from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from cloud_security.application.commands.asset_inventory_commands import (
    BatchAssetCommand,
    DeleteAssetCommand,
    MoveAssetCommand,
    TagAssetCommand,
    UntagAssetCommand,
    UpdateAssetCommand,
)
from cloud_security.application.dtos.asset_inventory_outcomes import BatchAssetStatus
from cloud_security.application.dtos.asset_query_outcome import AssetQueryStatus
from cloud_security.application.exceptions import (
    DuplicateAssetIdError,
    EmptyBatchAssetError,
    InvalidOwnershipError,
    InvalidRegionError,
    InvalidTagError,
)
from cloud_security.application.queries.asset_inventory_queries import (
    GetAssetQuery,
    ListAssetsByProviderQuery,
    ListAssetsByRegionQuery,
    ListAssetsByTypeQuery,
    ListAssetsQuery,
    SearchAssetsQuery,
)
from cloud_security.application.registry.in_memory_asset_inventory_registry import (
    InMemoryAssetInventoryRegistry,
)
from cloud_security.application.services.asset_inventory_application_service import (
    AssetInventoryApplicationService,
)
from cloud_security.domain.aggregates.cloud_asset import CloudAsset
from cloud_security.domain.exceptions.domain_exceptions import (
    InvalidAssetLifecycleTransition,
    TenantMismatch,
)
from cloud_security.domain.value_objects.cloud_metadata import CloudMetadata
from cloud_security.domain.value_objects.cloud_tag import CloudTag, CloudTagSet
from cloud_security.domain.value_objects.enums import (
    CloudAssetLifecycleState,
    CloudAssetType,
    CloudPlatformType,
    CloudRiskLevel,
)
from cloud_security.domain.value_objects.identifiers import AccountId, AssetId, RegionId, TenantId

from .conftest_inventory import FakeAssetInventoryProvider, make_register_command, make_resource

NOW = datetime.now(UTC)


def _service(registry=None):
    return AssetInventoryApplicationService(provider_registry=registry or InMemoryAssetInventoryRegistry())


def _discovered_asset(**overrides) -> CloudAsset:
    defaults = {
        "asset_id": AssetId.generate(),
        "tenant_id": TenantId.generate(),
        "account_id": AccountId.generate(),
        "resource": make_resource(),
        "tags": CloudTagSet(),
        "risk_level": CloudRiskLevel.LOW,
        "metadata": CloudMetadata(),
        "now": NOW,
    }
    defaults.update(overrides)
    return CloudAsset.discover(**defaults)


# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------


def test_register_asset_returns_dto() -> None:
    service = _service()

    outcome = service.register_asset(make_register_command())

    assert outcome.record.asset_type == CloudAssetType.COMPUTE_INSTANCE
    assert outcome.record.lifecycle_state == CloudAssetLifecycleState.ACTIVE


def test_register_asset_rejects_invalid_ownership() -> None:
    service = _service()
    cmd = dataclasses.replace(make_register_command(), account_id="not-an-account-id")

    with pytest.raises(InvalidOwnershipError):
        service.register_asset(cmd)


# ---------------------------------------------------------------------------
# updates / tagging
# ---------------------------------------------------------------------------


def test_update_asset_changes_risk_level() -> None:
    service = _service()
    asset = _discovered_asset()

    outcome = service.update_asset(
        asset, UpdateAssetCommand(tenant_id=asset.tenant_id, risk_level=CloudRiskLevel.CRITICAL)
    )

    assert outcome.record.risk_level == CloudRiskLevel.CRITICAL


def test_tag_asset() -> None:
    service = _service()
    asset = _discovered_asset()

    outcome = service.tag_asset(
        asset, TagAssetCommand(tenant_id=asset.tenant_id, tag=CloudTag(key="env", value="prod"))
    )

    assert "env" in outcome.record.tags


def test_untag_asset() -> None:
    service = _service()
    asset = _discovered_asset(tags=CloudTagSet(tags=(CloudTag(key="env", value="prod"),)))

    outcome = service.untag_asset(asset, UntagAssetCommand(tenant_id=asset.tenant_id, tag_key="env"))

    assert "env" not in outcome.record.tags


def test_untag_asset_rejects_empty_key() -> None:
    service = _service()
    asset = _discovered_asset()

    with pytest.raises(InvalidTagError):
        service.untag_asset(asset, UntagAssetCommand(tenant_id=asset.tenant_id, tag_key="  "))


def test_update_wrong_tenant_raises() -> None:
    service = _service()
    asset = _discovered_asset()

    with pytest.raises(TenantMismatch):
        service.update_asset(
            asset, UpdateAssetCommand(tenant_id=TenantId.generate(), risk_level=CloudRiskLevel.HIGH)
        )


# ---------------------------------------------------------------------------
# moving
# ---------------------------------------------------------------------------


def test_move_asset_changes_account() -> None:
    service = _service()
    asset = _discovered_asset()
    new_account = AccountId.generate()

    outcome = service.move_asset(
        asset, MoveAssetCommand(tenant_id=asset.tenant_id, account_id=new_account)
    )

    assert outcome.record.account_id == str(new_account)
    assert outcome.to_account_id == str(new_account)


def test_move_asset_rejects_invalid_ownership() -> None:
    service = _service()
    asset = _discovered_asset()

    with pytest.raises(InvalidOwnershipError):
        service.move_asset(
            asset, MoveAssetCommand(tenant_id=asset.tenant_id, account_id="not-an-account-id")
        )


def test_move_asset_rejects_invalid_region() -> None:
    service = _service()
    asset = _discovered_asset()

    with pytest.raises(InvalidRegionError):
        service.move_asset(
            asset, MoveAssetCommand(tenant_id=asset.tenant_id, region_id=RegionId("US EAST 1!"))
        )


# ---------------------------------------------------------------------------
# lifecycle / delete
# ---------------------------------------------------------------------------


def test_delete_asset_decommissions() -> None:
    service = _service()
    asset = _discovered_asset()

    outcome = service.delete_asset(asset, DeleteAssetCommand(tenant_id=asset.tenant_id))

    assert asset.lifecycle_state == CloudAssetLifecycleState.DECOMMISSIONED
    assert outcome.asset_id == str(asset.asset_id)


def test_delete_asset_twice_raises() -> None:
    service = _service()
    asset = _discovered_asset()
    service.delete_asset(asset, DeleteAssetCommand(tenant_id=asset.tenant_id))

    with pytest.raises(InvalidAssetLifecycleTransition):
        service.delete_asset(asset, DeleteAssetCommand(tenant_id=asset.tenant_id))


def test_update_after_delete_raises() -> None:
    service = _service()
    asset = _discovered_asset()
    service.delete_asset(asset, DeleteAssetCommand(tenant_id=asset.tenant_id))

    with pytest.raises(InvalidAssetLifecycleTransition):
        service.update_asset(
            asset, UpdateAssetCommand(tenant_id=asset.tenant_id, risk_level=CloudRiskLevel.HIGH)
        )


# ---------------------------------------------------------------------------
# batch registration
# ---------------------------------------------------------------------------


def test_batch_register_all_succeed() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    commands = tuple(
        make_register_command(tenant_id=tenant_id, resource=make_resource(f"i-{i}"))
        for i in range(3)
    )

    result = service.register_batch(BatchAssetCommand(tenant_id=tenant_id, commands=commands))

    assert result.status == BatchAssetStatus.SUCCEEDED
    assert result.succeeded_count == 3
    assert result.failed_count == 0


def test_batch_register_rejects_duplicate_resource_ids() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    resource = make_resource("i-dup")
    commands = (
        make_register_command(tenant_id=tenant_id, resource=resource),
        make_register_command(tenant_id=tenant_id, resource=resource),
    )

    with pytest.raises(DuplicateAssetIdError):
        service.register_batch(BatchAssetCommand(tenant_id=tenant_id, commands=commands))


def test_batch_register_empty_raises() -> None:
    service = _service()
    with pytest.raises(EmptyBatchAssetError):
        service.register_batch(BatchAssetCommand(tenant_id=TenantId.generate(), commands=()))


def test_batch_register_partial_failure() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    bad_cmd = dataclasses.replace(
        make_register_command(tenant_id=tenant_id, resource=make_resource("i-bad")),
        account_id="not-an-account-id",
    )
    good_cmd = make_register_command(tenant_id=tenant_id, resource=make_resource("i-good"))

    result = service.register_batch(
        BatchAssetCommand(tenant_id=tenant_id, commands=(good_cmd, bad_cmd))
    )

    assert result.status == BatchAssetStatus.PARTIALLY_SUCCEEDED
    assert result.succeeded_count == 1
    assert result.failed_count == 1


# ---------------------------------------------------------------------------
# queries
# ---------------------------------------------------------------------------


def test_get_asset_unsupported_provider() -> None:
    service = _service()
    outcome = service.get_asset(
        GetAssetQuery(
            tenant_id=TenantId.generate(),
            platform_type=CloudPlatformType.AWS,
            asset_id=AssetId.generate(),
        )
    )
    assert outcome.status == AssetQueryStatus.UNSUPPORTED_PROVIDER


def test_list_assets_succeeds() -> None:
    tenant_id = TenantId.generate()
    registry = InMemoryAssetInventoryRegistry()
    provider = FakeAssetInventoryProvider(CloudPlatformType.AWS)
    registry.register(provider)
    service = _service(registry)

    outcome = service.list_assets(
        ListAssetsQuery(tenant_id=tenant_id, platform_type=CloudPlatformType.AWS)
    )

    assert outcome.status == AssetQueryStatus.SUCCEEDED
    assert outcome.records == ()


def test_provider_execution_exception_produces_failed_outcome() -> None:
    registry = InMemoryAssetInventoryRegistry()
    provider = FakeAssetInventoryProvider(CloudPlatformType.AWS)
    provider.reader.raise_on_call = True
    registry.register(provider)
    service = _service(registry)

    outcome = service.list_assets(
        ListAssetsQuery(tenant_id=TenantId.generate(), platform_type=CloudPlatformType.AWS)
    )

    assert outcome.status == AssetQueryStatus.FAILED
    assert outcome.failures[0].error_type == "RuntimeError"


def test_list_assets_by_type_by_region_by_provider_and_search() -> None:
    registry = InMemoryAssetInventoryRegistry()
    registry.register(FakeAssetInventoryProvider(CloudPlatformType.AWS))
    service = _service(registry)
    tenant_id = TenantId.generate()

    assert service.list_assets_by_type(
        ListAssetsByTypeQuery(
            tenant_id=tenant_id,
            platform_type=CloudPlatformType.AWS,
            asset_type=CloudAssetType.COMPUTE_INSTANCE,
        )
    ).status == AssetQueryStatus.SUCCEEDED

    assert service.list_assets_by_region(
        ListAssetsByRegionQuery(
            tenant_id=tenant_id, platform_type=CloudPlatformType.AWS, region_id=RegionId("us-east-1")
        )
    ).status == AssetQueryStatus.SUCCEEDED

    assert service.list_assets_by_provider(
        ListAssetsByProviderQuery(tenant_id=tenant_id, platform_type=CloudPlatformType.AWS)
    ).status == AssetQueryStatus.SUCCEEDED

    assert service.search_assets(
        SearchAssetsQuery(
            tenant_id=tenant_id, platform_type=CloudPlatformType.AWS, filters={"tag:env": "prod"}
        )
    ).status == AssetQueryStatus.SUCCEEDED


# ---------------------------------------------------------------------------
# immutability
# ---------------------------------------------------------------------------


def test_asset_registered_outcome_is_frozen() -> None:
    service = _service()
    outcome = service.register_asset(make_register_command())
    with pytest.raises(dataclasses.FrozenInstanceError):
        outcome.record = None  # type: ignore[misc]


def test_batch_asset_result_is_frozen() -> None:
    service = _service()
    result = service.register_batch(
        BatchAssetCommand(tenant_id=TenantId.generate(), commands=(make_register_command(),))
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.status = BatchAssetStatus.FAILED  # type: ignore[misc]
