"""InMemoryCloudProviderRegistry — the one concrete registry this
milestone implements (M45A §4). Keyed by `CloudPlatformType`; duplicate
registration is a genuine error, never silently overwritten. No
persistence, no DI container wiring."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_security.application.exceptions import (
    DuplicateProviderRegistrationError,
    UnsupportedProviderError,
)

if TYPE_CHECKING:
    from cloud_security.application.ports.i_cloud_provider import ICloudProvider
    from cloud_security.domain.value_objects.enums import CloudPlatformType


class InMemoryCloudProviderRegistry:
    def __init__(self) -> None:
        self._by_platform_type: dict[CloudPlatformType, ICloudProvider] = {}

    def register(self, provider: ICloudProvider) -> None:
        if provider.platform_type in self._by_platform_type:
            raise DuplicateProviderRegistrationError(provider.platform_type)
        self._by_platform_type[provider.platform_type] = provider

    def resolve(self, platform_type: CloudPlatformType) -> ICloudProvider:
        provider = self._by_platform_type.get(platform_type)
        if provider is None:
            raise UnsupportedProviderError(platform_type)
        return provider

    def is_registered(self, platform_type: CloudPlatformType) -> bool:
        return platform_type in self._by_platform_type
