from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cloud_security.application.exceptions import DuplicateProviderForPlatformError
from cloud_security.application.registry.in_memory_provider_registry import (
    InMemoryProviderRegistry,
)
from cloud_security.domain.aggregates.cloud_provider_registration import CloudProviderRegistration
from cloud_security.domain.value_objects.enums import CloudPlatformType, ProviderCapability
from cloud_security.domain.value_objects.identifiers import ProviderId, TenantId
from cloud_security.domain.value_objects.provider_capability_set import ProviderCapabilitySet

NOW = datetime.now(UTC)


def _registration(tenant_id: TenantId, platform_type=CloudPlatformType.AWS, **overrides):
    defaults = {
        "provider_id": ProviderId.generate(),
        "tenant_id": tenant_id,
        "platform_type": platform_type,
        "display_name": "provider",
        "capabilities": ProviderCapabilitySet(),
        "now": NOW,
    }
    defaults.update(overrides)
    return CloudProviderRegistration.register(**defaults)


def test_register_then_get_returns_same_registration() -> None:
    registry = InMemoryProviderRegistry()
    tenant_id = TenantId.generate()
    registration = _registration(tenant_id)
    registry.register(registration)

    assert registry.get(tenant_id, registration.provider_id) is registration


def test_get_wrong_tenant_returns_none() -> None:
    registry = InMemoryProviderRegistry()
    registration = _registration(TenantId.generate())
    registry.register(registration)

    assert registry.get(TenantId.generate(), registration.provider_id) is None


def test_get_unknown_id_returns_none() -> None:
    registry = InMemoryProviderRegistry()
    assert registry.get(TenantId.generate(), ProviderId.generate()) is None


def test_duplicate_platform_for_same_tenant_raises() -> None:
    registry = InMemoryProviderRegistry()
    tenant_id = TenantId.generate()
    registry.register(_registration(tenant_id, CloudPlatformType.AWS))

    with pytest.raises(DuplicateProviderForPlatformError):
        registry.register(_registration(tenant_id, CloudPlatformType.AWS))


def test_same_platform_different_tenants_do_not_conflict() -> None:
    registry = InMemoryProviderRegistry()
    registry.register(_registration(TenantId.generate(), CloudPlatformType.AWS))
    registry.register(_registration(TenantId.generate(), CloudPlatformType.AWS))  # no raise


def test_different_platforms_same_tenant_do_not_conflict() -> None:
    registry = InMemoryProviderRegistry()
    tenant_id = TenantId.generate()
    registry.register(_registration(tenant_id, CloudPlatformType.AWS))
    registry.register(_registration(tenant_id, CloudPlatformType.AZURE))  # no raise


def test_is_platform_registered() -> None:
    registry = InMemoryProviderRegistry()
    tenant_id = TenantId.generate()
    registry.register(_registration(tenant_id, CloudPlatformType.AWS))

    assert registry.is_platform_registered(tenant_id, CloudPlatformType.AWS) is True
    assert registry.is_platform_registered(tenant_id, CloudPlatformType.GCP) is False


def test_list_scoped_to_tenant() -> None:
    registry = InMemoryProviderRegistry()
    tenant_a, tenant_b = TenantId.generate(), TenantId.generate()
    reg_a = _registration(tenant_a, CloudPlatformType.AWS)
    reg_b = _registration(tenant_b, CloudPlatformType.AZURE)
    registry.register(reg_a)
    registry.register(reg_b)

    assert registry.list(tenant_a) == (reg_a,)
    assert registry.list(tenant_b) == (reg_b,)


def test_list_by_platform() -> None:
    registry = InMemoryProviderRegistry()
    tenant_id = TenantId.generate()
    aws_reg = _registration(tenant_id, CloudPlatformType.AWS)
    azure_reg = _registration(tenant_id, CloudPlatformType.AZURE)
    registry.register(aws_reg)
    registry.register(azure_reg)

    assert registry.list_by_platform(tenant_id, CloudPlatformType.AWS) == (aws_reg,)


def test_list_enabled_only_returns_enabled() -> None:
    registry = InMemoryProviderRegistry()
    tenant_id = TenantId.generate()
    enabled = _registration(tenant_id, CloudPlatformType.AWS)
    disabled = _registration(tenant_id, CloudPlatformType.AZURE)
    registry.register(enabled)
    registry.register(disabled)
    enabled.enable(tenant_id, NOW)

    assert registry.list_enabled(tenant_id) == (enabled,)


def test_list_by_capability() -> None:
    registry = InMemoryProviderRegistry()
    tenant_id = TenantId.generate()
    with_discovery = _registration(
        tenant_id,
        CloudPlatformType.AWS,
        capabilities=ProviderCapabilitySet(capabilities=(ProviderCapability.DISCOVERY,)),
    )
    without = _registration(tenant_id, CloudPlatformType.AZURE)
    registry.register(with_discovery)
    registry.register(without)

    assert registry.list_by_capability(tenant_id, ProviderCapability.DISCOVERY) == (with_discovery,)
    assert registry.list_by_capability(tenant_id, ProviderCapability.STORAGE) == ()
