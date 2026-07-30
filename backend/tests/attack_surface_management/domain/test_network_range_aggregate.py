from __future__ import annotations

from datetime import UTC, datetime

import pytest

from attack_surface_management.domain.events.network_range_events import (
    NetworkRangeActivated,
    NetworkRangeAssetCountUpdated,
    NetworkRangeDiscovered,
    NetworkRangeRetired,
)
from attack_surface_management.domain.exceptions.domain_exceptions import (
    InvalidNegativeCountError,
    InvalidNetworkRangeLifecycleTransition,
    TenantMismatch,
)
from attack_surface_management.domain.factories.network_range_factory import (
    NetworkRangeFactory,
)
from attack_surface_management.domain.value_objects.cidr_block import CidrBlock
from attack_surface_management.domain.value_objects.enums import NetworkRangeLifecycleState
from attack_surface_management.domain.value_objects.identifiers import TenantId

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _create(tenant_id: TenantId):
    return NetworkRangeFactory.discover(tenant_id=tenant_id, cidr=CidrBlock("10.0.0.0/24"), now=NOW)


def test_factory_creates_and_emits_discovered_event(tenant_id: TenantId) -> None:
    net_range = _create(tenant_id)
    assert net_range.lifecycle_state == NetworkRangeLifecycleState.DISCOVERED
    assert net_range.asset_count == 0
    events = net_range.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], NetworkRangeDiscovered)


def test_record_asset_count_emits_event_only_on_change(tenant_id: TenantId) -> None:
    net_range = _create(tenant_id)
    net_range.pop_events()
    net_range.record_asset_count(tenant_id, 5, NOW)
    assert net_range.asset_count == 5
    events = net_range.pop_events()
    assert any(isinstance(e, NetworkRangeAssetCountUpdated) for e in events)

    net_range.record_asset_count(tenant_id, 5, NOW)
    assert net_range.pop_events() == []


def test_record_negative_asset_count_raises(tenant_id: TenantId) -> None:
    net_range = _create(tenant_id)
    with pytest.raises(InvalidNegativeCountError):
        net_range.record_asset_count(tenant_id, -1, NOW)


def test_lifecycle_happy_path(tenant_id: TenantId) -> None:
    net_range = _create(tenant_id)
    net_range.pop_events()
    net_range.activate(tenant_id, NOW)
    assert net_range.lifecycle_state == NetworkRangeLifecycleState.ACTIVE
    net_range.retire(tenant_id, NOW)
    assert net_range.lifecycle_state == NetworkRangeLifecycleState.RETIRED
    events = net_range.pop_events()
    assert any(isinstance(e, NetworkRangeActivated) for e in events)
    assert any(isinstance(e, NetworkRangeRetired) for e in events)


def test_retire_is_terminal(tenant_id: TenantId) -> None:
    net_range = _create(tenant_id)
    net_range.activate(tenant_id, NOW)
    net_range.retire(tenant_id, NOW)
    with pytest.raises(InvalidNetworkRangeLifecycleTransition):
        net_range.activate(tenant_id, NOW)


def test_discovered_cannot_retire_directly(tenant_id: TenantId) -> None:
    net_range = _create(tenant_id)
    with pytest.raises(InvalidNetworkRangeLifecycleTransition):
        net_range.retire(tenant_id, NOW)


def test_tenant_mismatch_raised(tenant_id: TenantId) -> None:
    net_range = _create(tenant_id)
    other = TenantId.generate()
    with pytest.raises(TenantMismatch):
        net_range.activate(other, NOW)
