from __future__ import annotations

import pytest

from cloud_security.application.exceptions import (
    DuplicateProviderRegistrationError,
    UnsupportedProviderError,
)
from cloud_security.application.registry.in_memory_cloud_provider_registry import (
    InMemoryCloudProviderRegistry,
)
from cloud_security.domain.value_objects.enums import CloudPlatformType


class FakeCloudProvider:
    def __init__(self, platform_type: CloudPlatformType) -> None:
        self._platform_type = platform_type

    @property
    def platform_type(self) -> CloudPlatformType:
        return self._platform_type


def test_register_then_resolve_returns_same_provider() -> None:
    registry = InMemoryCloudProviderRegistry()
    provider = FakeCloudProvider(CloudPlatformType.AWS)
    registry.register(provider)

    assert registry.resolve(CloudPlatformType.AWS) is provider


def test_is_registered() -> None:
    registry = InMemoryCloudProviderRegistry()
    registry.register(FakeCloudProvider(CloudPlatformType.AWS))

    assert registry.is_registered(CloudPlatformType.AWS) is True
    assert registry.is_registered(CloudPlatformType.AZURE) is False


def test_duplicate_registration_raises() -> None:
    registry = InMemoryCloudProviderRegistry()
    registry.register(FakeCloudProvider(CloudPlatformType.AWS))

    with pytest.raises(DuplicateProviderRegistrationError):
        registry.register(FakeCloudProvider(CloudPlatformType.AWS))


def test_different_platform_types_do_not_conflict() -> None:
    registry = InMemoryCloudProviderRegistry()
    registry.register(FakeCloudProvider(CloudPlatformType.AWS))
    registry.register(FakeCloudProvider(CloudPlatformType.AZURE))

    assert registry.is_registered(CloudPlatformType.AWS)
    assert registry.is_registered(CloudPlatformType.AZURE)


def test_resolve_unregistered_platform_raises() -> None:
    registry = InMemoryCloudProviderRegistry()
    with pytest.raises(UnsupportedProviderError):
        registry.resolve(CloudPlatformType.GCP)
