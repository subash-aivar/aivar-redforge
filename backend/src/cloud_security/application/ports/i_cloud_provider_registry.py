"""ICloudProviderRegistry — registration/lookup contract for
`ICloudProvider` implementations (M45A §4).

Keyed by `CloudPlatformType` alone — unlike the SIEM engines'
schema-version-compatible registries, a cloud platform integration has
no CEM-style schema version to negotiate (mirrors `siem_storage`'s
`StorageTier`-only registry, the one precedent in the frozen SIEM
architecture without a `SchemaVersion` dimension).
`InMemoryCloudProviderRegistry` (M45A §4) is this milestone's one
concrete implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from cloud_security.application.ports.i_cloud_provider import ICloudProvider
    from cloud_security.domain.value_objects.enums import CloudPlatformType


class ICloudProviderRegistry(Protocol):
    def register(self, provider: ICloudProvider) -> None:
        """Raises `DuplicateProviderRegistrationError` if a provider
        for the same `platform_type` is already registered."""
        ...

    def resolve(self, platform_type: CloudPlatformType) -> ICloudProvider:
        """Raises `UnsupportedProviderError` if `platform_type` has no
        registration."""
        ...

    def is_registered(self, platform_type: CloudPlatformType) -> bool: ...
