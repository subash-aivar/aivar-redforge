"""IProviderRegistry — the Provider Framework's registration/lookup
contract (M45C).

Unlike `ICloudProviderRegistry` (M45A) or `IAssetInventoryRegistry`
(M45B) — which resolve an external plug-in implementation keyed by
`CloudPlatformType` — this registry *is* the framework's own store of
`CloudProviderRegistration` aggregates. It owns registration, lookup,
duplicate prevention, capability lookup, and platform-compatibility
lookup; it never resolves or calls a cloud SDK.
`InMemoryProviderRegistry` (M45C) is this milestone's one concrete
implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.domain.aggregates.cloud_provider_registration import (
        CloudProviderRegistration,
    )
    from cloud_security.domain.value_objects.enums import CloudPlatformType, ProviderCapability
    from cloud_security.domain.value_objects.identifiers import ProviderId, TenantId


class IProviderRegistry(Protocol):
    def register(self, registration: CloudProviderRegistration) -> None:
        """Raises `DuplicateProviderForPlatformError` if the same
        tenant already has a registration for that `platform_type`."""
        ...

    def get(
        self, tenant_id: TenantId, provider_id: ProviderId
    ) -> CloudProviderRegistration | None: ...

    def list(self, tenant_id: TenantId) -> Sequence[CloudProviderRegistration]: ...

    def list_by_platform(
        self, tenant_id: TenantId, platform_type: CloudPlatformType
    ) -> Sequence[CloudProviderRegistration]: ...

    def list_enabled(self, tenant_id: TenantId) -> Sequence[CloudProviderRegistration]: ...

    def list_by_capability(
        self, tenant_id: TenantId, capability: ProviderCapability
    ) -> Sequence[CloudProviderRegistration]: ...

    def is_platform_registered(
        self, tenant_id: TenantId, platform_type: CloudPlatformType
    ) -> bool: ...
