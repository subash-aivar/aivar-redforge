from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cloud_security.domain.aggregates.cloud_provider_registration import CloudProviderRegistration
from cloud_security.domain.events.provider_events import (
    ProviderDisabled,
    ProviderEnabled,
    ProviderRegistered,
    ProviderRemoved,
    ProviderUpdated,
)
from cloud_security.domain.exceptions.domain_exceptions import (
    EmptyDisplayNameError,
    InvalidProviderTransition,
    TenantMismatch,
)
from cloud_security.domain.value_objects.enums import (
    CloudPlatformType,
    ProviderCapability,
    ProviderStatus,
)
from cloud_security.domain.value_objects.identifiers import ProviderId, TenantId
from cloud_security.domain.value_objects.provider_capability_set import ProviderCapabilitySet

NOW = datetime.now(UTC)


def _register(**overrides) -> CloudProviderRegistration:
    defaults = {
        "provider_id": ProviderId.generate(),
        "tenant_id": TenantId.generate(),
        "platform_type": CloudPlatformType.AWS,
        "display_name": "aws-primary",
        "capabilities": ProviderCapabilitySet(),
        "now": NOW,
    }
    defaults.update(overrides)
    return CloudProviderRegistration.register(**defaults)


def test_register_starts_disabled_and_emits_event() -> None:
    registration = _register()
    assert registration.status == ProviderStatus.DISABLED

    events = registration.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], ProviderRegistered)
    assert events[0].platform_type == CloudPlatformType.AWS

    assert registration.pop_events() == []


def test_register_rejects_empty_display_name() -> None:
    with pytest.raises(EmptyDisplayNameError):
        _register(display_name="  ")


def test_enable_disable_cycle() -> None:
    registration = _register()
    registration.pop_events()
    tenant_id = registration.tenant_id

    registration.enable(tenant_id, NOW)
    assert registration.status == ProviderStatus.ENABLED
    events = registration.pop_events()
    assert isinstance(events[0], ProviderEnabled)

    registration.disable(tenant_id, NOW)
    assert registration.status == ProviderStatus.DISABLED
    events = registration.pop_events()
    assert isinstance(events[0], ProviderDisabled)


def test_enable_twice_raises() -> None:
    registration = _register()
    registration.enable(registration.tenant_id, NOW)

    with pytest.raises(InvalidProviderTransition):
        registration.enable(registration.tenant_id, NOW)


def test_disable_without_enable_raises() -> None:
    registration = _register()
    with pytest.raises(InvalidProviderTransition):
        registration.disable(registration.tenant_id, NOW)


def test_remove_from_disabled_and_enabled() -> None:
    registration = _register()
    registration.remove(registration.tenant_id, NOW)
    assert registration.status == ProviderStatus.REMOVED

    registration2 = _register()
    registration2.enable(registration2.tenant_id, NOW)
    registration2.remove(registration2.tenant_id, NOW)
    assert registration2.status == ProviderStatus.REMOVED


def test_remove_emits_event() -> None:
    registration = _register()
    registration.pop_events()
    registration.remove(registration.tenant_id, NOW)
    events = registration.pop_events()
    assert isinstance(events[0], ProviderRemoved)


def test_remove_twice_raises() -> None:
    registration = _register()
    registration.remove(registration.tenant_id, NOW)
    with pytest.raises(InvalidProviderTransition):
        registration.remove(registration.tenant_id, NOW)


def test_enable_after_removed_raises() -> None:
    registration = _register()
    registration.remove(registration.tenant_id, NOW)
    with pytest.raises(InvalidProviderTransition):
        registration.enable(registration.tenant_id, NOW)


def test_update_display_name_and_capabilities() -> None:
    registration = _register()
    registration.pop_events()
    new_caps = ProviderCapabilitySet(capabilities=(ProviderCapability.DISCOVERY,))

    registration.update(registration.tenant_id, NOW, display_name="renamed", capabilities=new_caps)

    assert registration.display_name == "renamed"
    assert ProviderCapability.DISCOVERY in registration.capabilities
    events = registration.pop_events()
    assert isinstance(events[0], ProviderUpdated)
    assert set(events[0].updated_fields) == {"display_name", "capabilities"}


def test_update_with_no_fields_is_noop() -> None:
    registration = _register()
    registration.pop_events()
    original_updated_at = registration.updated_at

    registration.update(registration.tenant_id, NOW)

    assert registration.updated_at == original_updated_at
    assert registration.pop_events() == []


def test_update_rejects_empty_display_name() -> None:
    registration = _register()
    with pytest.raises(EmptyDisplayNameError):
        registration.update(registration.tenant_id, NOW, display_name="   ")


def test_update_after_removed_raises() -> None:
    registration = _register()
    registration.remove(registration.tenant_id, NOW)
    with pytest.raises(InvalidProviderTransition):
        registration.update(registration.tenant_id, NOW, display_name="x")


def test_wrong_tenant_raises_on_every_mutator() -> None:
    registration = _register()
    other_tenant = TenantId.generate()

    with pytest.raises(TenantMismatch):
        registration.enable(other_tenant, NOW)
    with pytest.raises(TenantMismatch):
        registration.disable(other_tenant, NOW)
    with pytest.raises(TenantMismatch):
        registration.remove(other_tenant, NOW)
    with pytest.raises(TenantMismatch):
        registration.update(other_tenant, NOW, display_name="x")
