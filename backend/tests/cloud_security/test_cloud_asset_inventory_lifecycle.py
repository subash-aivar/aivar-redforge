from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cloud_security.domain.aggregates.cloud_asset import CloudAsset
from cloud_security.domain.events.cloud_asset_events import AssetDecommissioned, AssetMoved
from cloud_security.domain.exceptions.domain_exceptions import (
    EmptyMoveError,
    InvalidAssetLifecycleTransition,
    TenantMismatch,
)
from cloud_security.domain.value_objects.cloud_metadata import CloudMetadata
from cloud_security.domain.value_objects.cloud_resource import CloudResource
from cloud_security.domain.value_objects.cloud_tag import CloudTag, CloudTagSet
from cloud_security.domain.value_objects.enums import (
    CloudAssetLifecycleState,
    CloudAssetType,
    CloudRiskLevel,
)
from cloud_security.domain.value_objects.identifiers import (
    AccountId,
    AssetId,
    RegionId,
    ResourceId,
    TenantId,
)

NOW = datetime.now(UTC)


def _discover(**overrides) -> CloudAsset:
    defaults = {
        "asset_id": AssetId.generate(),
        "tenant_id": TenantId.generate(),
        "account_id": AccountId.generate(),
        "resource": CloudResource(
            resource_id=ResourceId("res-1"),
            native_id="i-1",
            asset_type=CloudAssetType.COMPUTE_INSTANCE,
            region_id=RegionId("us-east-1"),
        ),
        "tags": CloudTagSet(),
        "risk_level": CloudRiskLevel.LOW,
        "metadata": CloudMetadata(),
        "now": NOW,
    }
    defaults.update(overrides)
    return CloudAsset.discover(**defaults)


def test_new_asset_defaults_to_active() -> None:
    asset = _discover()
    assert asset.lifecycle_state == CloudAssetLifecycleState.ACTIVE


def test_add_tag_appends_and_emits_updated() -> None:
    asset = _discover()
    asset.pop_events()

    asset.add_tag(asset.tenant_id, CloudTag(key="env", value="prod"), NOW)

    assert "env" in asset.tags
    events = asset.pop_events()
    assert events[0].updated_fields == ("tags",)


def test_remove_tag() -> None:
    asset = _discover(tags=CloudTagSet(tags=(CloudTag(key="env", value="prod"),)))
    asset.pop_events()

    asset.remove_tag(asset.tenant_id, "env", NOW)

    assert "env" not in asset.tags


def test_move_account_only() -> None:
    asset = _discover()
    asset.pop_events()
    new_account = AccountId.generate()

    asset.move(asset.tenant_id, NOW, account_id=new_account)

    assert asset.account_id == new_account
    events = asset.pop_events()
    assert isinstance(events[0], AssetMoved)
    assert events[0].to_account_id == str(new_account)


def test_move_region_only() -> None:
    asset = _discover()
    asset.pop_events()
    new_region = RegionId("eu-west-1")

    asset.move(asset.tenant_id, NOW, region_id=new_region)

    assert asset.resource.region_id == new_region


def test_move_requires_at_least_one_target() -> None:
    asset = _discover()
    with pytest.raises(EmptyMoveError):
        asset.move(asset.tenant_id, NOW)


def test_move_wrong_tenant_raises() -> None:
    asset = _discover()
    with pytest.raises(TenantMismatch):
        asset.move(TenantId.generate(), NOW, account_id=AccountId.generate())


def test_decommission_emits_event_and_sets_terminal_state() -> None:
    asset = _discover()
    asset.pop_events()

    asset.decommission(asset.tenant_id, NOW)

    assert asset.lifecycle_state == CloudAssetLifecycleState.DECOMMISSIONED
    events = asset.pop_events()
    assert isinstance(events[0], AssetDecommissioned)


def test_decommission_twice_raises() -> None:
    asset = _discover()
    asset.decommission(asset.tenant_id, NOW)

    with pytest.raises(InvalidAssetLifecycleTransition):
        asset.decommission(asset.tenant_id, NOW)


def test_update_after_decommission_raises() -> None:
    asset = _discover()
    asset.decommission(asset.tenant_id, NOW)

    with pytest.raises(InvalidAssetLifecycleTransition):
        asset.update(asset.tenant_id, NOW, risk_level=CloudRiskLevel.HIGH)


def test_move_after_decommission_raises() -> None:
    asset = _discover()
    asset.decommission(asset.tenant_id, NOW)

    with pytest.raises(InvalidAssetLifecycleTransition):
        asset.move(asset.tenant_id, NOW, account_id=AccountId.generate())
