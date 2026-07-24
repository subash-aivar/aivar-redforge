from __future__ import annotations

import pytest

from cloud_security.application.exceptions import (
    DuplicateProviderRegistrationError,
    UnsupportedProviderError,
)
from cloud_security.application.registry.in_memory_asset_inventory_registry import (
    InMemoryAssetInventoryRegistry,
)
from cloud_security.domain.value_objects.enums import CloudPlatformType

from .conftest_inventory import FakeAssetInventoryProvider


def test_register_then_resolve_returns_same_provider() -> None:
    registry = InMemoryAssetInventoryRegistry()
    provider = FakeAssetInventoryProvider(CloudPlatformType.AWS)
    registry.register(provider)

    assert registry.resolve(CloudPlatformType.AWS) is provider


def test_is_registered() -> None:
    registry = InMemoryAssetInventoryRegistry()
    registry.register(FakeAssetInventoryProvider(CloudPlatformType.AWS))

    assert registry.is_registered(CloudPlatformType.AWS) is True
    assert registry.is_registered(CloudPlatformType.AZURE) is False


def test_duplicate_registration_raises() -> None:
    registry = InMemoryAssetInventoryRegistry()
    registry.register(FakeAssetInventoryProvider(CloudPlatformType.AWS))

    with pytest.raises(DuplicateProviderRegistrationError):
        registry.register(FakeAssetInventoryProvider(CloudPlatformType.AWS))


def test_different_platform_types_do_not_conflict() -> None:
    registry = InMemoryAssetInventoryRegistry()
    registry.register(FakeAssetInventoryProvider(CloudPlatformType.AWS))
    registry.register(FakeAssetInventoryProvider(CloudPlatformType.AZURE))

    assert registry.is_registered(CloudPlatformType.AWS)
    assert registry.is_registered(CloudPlatformType.AZURE)


def test_resolve_unregistered_platform_raises() -> None:
    registry = InMemoryAssetInventoryRegistry()
    with pytest.raises(UnsupportedProviderError):
        registry.resolve(CloudPlatformType.GCP)
