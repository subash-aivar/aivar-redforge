from __future__ import annotations

from datetime import UTC, datetime

from cloud_security.domain.aggregates.cloud_asset import CloudAsset
from cloud_security.domain.events.cloud_asset_events import AssetDiscovered, AssetUpdated
from cloud_security.domain.value_objects.cloud_metadata import CloudMetadata
from cloud_security.domain.value_objects.cloud_resource import CloudResource
from cloud_security.domain.value_objects.cloud_tag import CloudTag, CloudTagSet
from cloud_security.domain.value_objects.enums import CloudAssetType, CloudRiskLevel
from cloud_security.domain.value_objects.identifiers import AccountId, AssetId, ResourceId, TenantId

NOW = datetime.now(UTC)


def _resource(**overrides) -> CloudResource:
    defaults = {
        "resource_id": ResourceId("res-1"),
        "native_id": "i-0123456789",
        "asset_type": CloudAssetType.COMPUTE_INSTANCE,
    }
    defaults.update(overrides)
    return CloudResource(**defaults)


def _discover(**overrides) -> CloudAsset:
    defaults = {
        "asset_id": AssetId.generate(),
        "tenant_id": TenantId.generate(),
        "account_id": AccountId.generate(),
        "resource": _resource(),
        "tags": CloudTagSet(),
        "risk_level": CloudRiskLevel.LOW,
        "metadata": CloudMetadata(),
        "now": NOW,
    }
    defaults.update(overrides)
    return CloudAsset.discover(**defaults)


def test_discover_emits_event() -> None:
    asset = _discover()
    events = asset.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], AssetDiscovered)
    assert events[0].asset_type == CloudAssetType.COMPUTE_INSTANCE
    assert asset.discovered_at == asset.updated_at


def test_update_risk_level_emits_event_and_bumps_updated_at() -> None:
    asset = _discover()
    asset.pop_events()
    later = datetime.now(UTC)

    asset.update(tenant_id=asset.tenant_id, now=later, risk_level=CloudRiskLevel.CRITICAL)

    assert asset.risk_level == CloudRiskLevel.CRITICAL
    assert asset.updated_at == later
    events = asset.pop_events()
    assert isinstance(events[0], AssetUpdated)
    assert events[0].updated_fields == ("risk_level",)


def test_update_with_no_fields_is_a_noop() -> None:
    asset = _discover()
    asset.pop_events()
    original_updated_at = asset.updated_at

    asset.update(tenant_id=asset.tenant_id, now=datetime.now(UTC))

    assert asset.updated_at == original_updated_at
    assert asset.pop_events() == []


def test_update_multiple_fields_lists_all_in_event() -> None:
    asset = _discover()
    asset.pop_events()
    tags = CloudTagSet(tags=(CloudTag(key="env", value="prod"),))

    asset.update(tenant_id=asset.tenant_id, now=NOW, tags=tags, risk_level=CloudRiskLevel.HIGH)

    events = asset.pop_events()
    assert set(events[0].updated_fields) == {"tags", "risk_level"}
