"""IAssetInventoryRegistry — registration/lookup contract for
`IAssetInventoryProvider` implementations (M45B).

`InMemoryAssetInventoryRegistry` (M45B) is this milestone's one
concrete implementation. Keyed by `CloudPlatformType`, mirroring
`ICloudProviderRegistry` (M45A)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from cloud_security.application.ports.i_asset_inventory_provider import (
        IAssetInventoryProvider,
    )
    from cloud_security.domain.value_objects.enums import CloudPlatformType


class IAssetInventoryRegistry(Protocol):
    def register(self, provider: IAssetInventoryProvider) -> None:
        """Raises `DuplicateProviderRegistrationError` if a provider
        for the same `platform_type` is already registered."""
        ...

    def resolve(self, platform_type: CloudPlatformType) -> IAssetInventoryProvider:
        """Raises `UnsupportedProviderError` if `platform_type` has no
        registration."""
        ...

    def is_registered(self, platform_type: CloudPlatformType) -> bool: ...
