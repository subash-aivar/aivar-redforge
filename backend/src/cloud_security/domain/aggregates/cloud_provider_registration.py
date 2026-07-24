"""CloudProviderRegistration aggregate — a tenant's registration of one
cloud platform into the Provider Framework, its claimed capabilities,
and its enable/disable/remove lifecycle (M45C).

Deliberately metadata-only: this aggregate never calls a cloud SDK,
never discovers resources, never validates a capability against what a
platform can actually do. It owns registration, capability bookkeeping,
and lifecycle state — nothing else. `ICloudProvider`/`ICloudDiscoveryProvider`
(M45A) remain the actual plug-in extension points a future
infrastructure milestone implements; this aggregate is the framework
that tracks *which* platforms have been registered and whether they
are currently enabled."""

from __future__ import annotations

from typing import TYPE_CHECKING

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
from cloud_security.domain.value_objects.enums import ProviderStatus

if TYPE_CHECKING:
    from datetime import datetime

    from cloud_security.domain.events.base import BaseDomainEvent
    from cloud_security.domain.value_objects.enums import CloudPlatformType
    from cloud_security.domain.value_objects.identifiers import ProviderId, TenantId
    from cloud_security.domain.value_objects.provider_capability_set import (
        ProviderCapabilitySet,
    )

_ENABLE_FROM = {ProviderStatus.DISABLED}
_DISABLE_FROM = {ProviderStatus.ENABLED}
_REMOVE_FROM = {ProviderStatus.ENABLED, ProviderStatus.DISABLED}


class CloudProviderRegistration:
    __slots__ = (
        "_pending_events",
        "capabilities",
        "display_name",
        "platform_type",
        "provider_id",
        "registered_at",
        "status",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        provider_id: ProviderId,
        tenant_id: TenantId,
        platform_type: CloudPlatformType,
        display_name: str,
        capabilities: ProviderCapabilitySet,
        status: ProviderStatus,
        registered_at: datetime,
        updated_at: datetime,
    ) -> None:
        self.provider_id = provider_id
        self.tenant_id = tenant_id
        self.platform_type = platform_type
        self.display_name = display_name
        self.capabilities = capabilities
        self.status = status
        self.registered_at = registered_at
        self.updated_at = updated_at
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _assert_not_removed(self) -> None:
        if self.status == ProviderStatus.REMOVED:
            raise InvalidProviderTransition(self.status.value, "mutated")

    @classmethod
    def register(
        cls,
        provider_id: ProviderId,
        tenant_id: TenantId,
        platform_type: CloudPlatformType,
        display_name: str,
        capabilities: ProviderCapabilitySet,
        now: datetime,
    ) -> CloudProviderRegistration:
        if not display_name.strip():
            raise EmptyDisplayNameError()
        registration = cls(
            provider_id=provider_id,
            tenant_id=tenant_id,
            platform_type=platform_type,
            display_name=display_name,
            capabilities=capabilities,
            status=ProviderStatus.DISABLED,
            registered_at=now,
            updated_at=now,
        )
        registration._emit(
            ProviderRegistered(
                tenant_id=str(tenant_id),
                aggregate_id=str(provider_id),
                aggregate_type="CloudProviderRegistration",
                occurred_at=now,
                platform_type=platform_type,
                display_name=display_name,
            )
        )
        return registration

    def update(
        self,
        tenant_id: TenantId,
        now: datetime,
        display_name: str | None = None,
        capabilities: ProviderCapabilitySet | None = None,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_removed()
        updated_fields: list[str] = []
        if display_name is not None:
            if not display_name.strip():
                raise EmptyDisplayNameError()
            self.display_name = display_name
            updated_fields.append("display_name")
        if capabilities is not None:
            self.capabilities = capabilities
            updated_fields.append("capabilities")
        if not updated_fields:
            return
        self.updated_at = now
        self._emit(
            ProviderUpdated(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.provider_id),
                aggregate_type="CloudProviderRegistration",
                occurred_at=now,
                updated_fields=tuple(updated_fields),
            )
        )

    def enable(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status not in _ENABLE_FROM:
            raise InvalidProviderTransition(self.status.value, ProviderStatus.ENABLED.value)
        self.status = ProviderStatus.ENABLED
        self.updated_at = now
        self._emit(
            ProviderEnabled(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.provider_id),
                aggregate_type="CloudProviderRegistration",
                occurred_at=now,
            )
        )

    def disable(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status not in _DISABLE_FROM:
            raise InvalidProviderTransition(self.status.value, ProviderStatus.DISABLED.value)
        self.status = ProviderStatus.DISABLED
        self.updated_at = now
        self._emit(
            ProviderDisabled(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.provider_id),
                aggregate_type="CloudProviderRegistration",
                occurred_at=now,
            )
        )

    def remove(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status not in _REMOVE_FROM:
            raise InvalidProviderTransition(self.status.value, ProviderStatus.REMOVED.value)
        self.status = ProviderStatus.REMOVED
        self.updated_at = now
        self._emit(
            ProviderRemoved(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.provider_id),
                aggregate_type="CloudProviderRegistration",
                occurred_at=now,
            )
        )
