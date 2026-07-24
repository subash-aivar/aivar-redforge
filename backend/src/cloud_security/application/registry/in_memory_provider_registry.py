"""InMemoryProviderRegistry — the one concrete registry this milestone
implements (M45C). Stores `CloudProviderRegistration` aggregates
in-memory, keyed by `provider_id`, with a secondary uniqueness
constraint of one registration per `(tenant_id, platform_type)` pair.
No persistence, no DI container wiring, no cloud SDK calls."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_security.application.exceptions import DuplicateProviderForPlatformError
from cloud_security.domain.value_objects.enums import ProviderStatus

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.domain.aggregates.cloud_provider_registration import (
        CloudProviderRegistration,
    )
    from cloud_security.domain.value_objects.enums import CloudPlatformType, ProviderCapability
    from cloud_security.domain.value_objects.identifiers import ProviderId, TenantId


class InMemoryProviderRegistry:
    def __init__(self) -> None:
        self._by_provider_id: dict[str, CloudProviderRegistration] = {}
        self._by_tenant_platform: dict[tuple[str, str], ProviderId] = {}

    def register(self, registration: CloudProviderRegistration) -> None:
        key = (str(registration.tenant_id), registration.platform_type.value)
        if key in self._by_tenant_platform:
            raise DuplicateProviderForPlatformError(
                registration.tenant_id, registration.platform_type
            )
        self._by_provider_id[str(registration.provider_id)] = registration
        self._by_tenant_platform[key] = registration.provider_id

    def get(
        self, tenant_id: TenantId, provider_id: ProviderId
    ) -> CloudProviderRegistration | None:
        registration = self._by_provider_id.get(str(provider_id))
        if registration is None or registration.tenant_id != tenant_id:
            return None
        return registration

    def list(self, tenant_id: TenantId) -> Sequence[CloudProviderRegistration]:
        return tuple(r for r in self._by_provider_id.values() if r.tenant_id == tenant_id)

    def list_by_platform(
        self, tenant_id: TenantId, platform_type: CloudPlatformType
    ) -> Sequence[CloudProviderRegistration]:
        return tuple(
            r
            for r in self._by_provider_id.values()
            if r.tenant_id == tenant_id and r.platform_type == platform_type
        )

    def list_enabled(self, tenant_id: TenantId) -> Sequence[CloudProviderRegistration]:
        return tuple(
            r
            for r in self._by_provider_id.values()
            if r.tenant_id == tenant_id and r.status == ProviderStatus.ENABLED
        )

    def list_by_capability(
        self, tenant_id: TenantId, capability: ProviderCapability
    ) -> Sequence[CloudProviderRegistration]:
        return tuple(
            r
            for r in self._by_provider_id.values()
            if r.tenant_id == tenant_id and capability in r.capabilities
        )

    def is_platform_registered(
        self, tenant_id: TenantId, platform_type: CloudPlatformType
    ) -> bool:
        return (str(tenant_id), platform_type.value) in self._by_tenant_platform
