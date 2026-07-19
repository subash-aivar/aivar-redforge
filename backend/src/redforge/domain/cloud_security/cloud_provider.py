"""CloudProvider aggregate root."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from redforge.domain.cloud_security.events import (
    CloudProviderDisabled,
    CloudProviderRegistered,
    CloudProviderUpdated,
    CloudSecurityDomainEvent,
)
from redforge.domain.cloud_security.exceptions import (
    CloudProviderDisabledError,
    InvalidCloudArgumentError,
)
from redforge.domain.cloud_security.value_objects import (
    CloudProviderId,
    CloudProviderStatus,
    CloudProviderType,
    DiscoveryConfig,
    OrganizationId,
)


@dataclass
class CloudProvider:
    id: CloudProviderId
    organization_id: OrganizationId
    provider_type: CloudProviderType
    display_name: str
    discovery_config: DiscoveryConfig
    status: CloudProviderStatus
    created_at: datetime
    updated_at: datetime
    version: int = 1
    _pending_events: list[CloudSecurityDomainEvent] = field(default_factory=list, repr=False)

    @classmethod
    def register(
        cls,
        *,
        organization_id: OrganizationId,
        provider_type: CloudProviderType,
        display_name: str,
        discovery_config: DiscoveryConfig | None = None,
        now: datetime | None = None,
        provider_id: CloudProviderId | None = None,
    ) -> CloudProvider:
        name = display_name.strip() if display_name else ""
        if not name:
            raise InvalidCloudArgumentError("display_name", "required")
        if len(name) > 256:
            raise InvalidCloudArgumentError("display_name", "max 256 chars")
        ts = now or datetime.now(UTC)
        aggregate = cls(
            id=provider_id or CloudProviderId.generate(),
            organization_id=organization_id,
            provider_type=provider_type,
            display_name=name,
            discovery_config=discovery_config or DiscoveryConfig(),
            status=CloudProviderStatus.ACTIVE,
            created_at=ts,
            updated_at=ts,
            version=1,
        )
        aggregate._pending_events.append(
            CloudProviderRegistered(
                provider_id=str(aggregate.id),
                organization_id=str(organization_id),
                provider_type=provider_type.value,
                display_name=name,
                occurred_at=ts,
            )
        )
        return aggregate

    def update(
        self,
        *,
        display_name: str | None = None,
        discovery_config: DiscoveryConfig | None = None,
        now: datetime | None = None,
    ) -> None:
        if self.status is CloudProviderStatus.DISABLED:
            raise CloudProviderDisabledError(str(self.id))
        changed = False
        if display_name is not None:
            name = display_name.strip()
            if not name:
                raise InvalidCloudArgumentError("display_name", "required")
            if len(name) > 256:
                raise InvalidCloudArgumentError("display_name", "max 256 chars")
            if name != self.display_name:
                self.display_name = name
                changed = True
        if discovery_config is not None and discovery_config != self.discovery_config:
            self.discovery_config = discovery_config
            changed = True
        if not changed:
            return
        ts = now or datetime.now(UTC)
        self.updated_at = ts
        self.version += 1
        self._pending_events.append(
            CloudProviderUpdated(
                provider_id=str(self.id),
                organization_id=str(self.organization_id),
                display_name=self.display_name,
                occurred_at=ts,
            )
        )

    def disable(self, *, now: datetime | None = None) -> None:
        if self.status is CloudProviderStatus.DISABLED:
            return
        ts = now or datetime.now(UTC)
        self.status = CloudProviderStatus.DISABLED
        self.updated_at = ts
        self.version += 1
        self._pending_events.append(
            CloudProviderDisabled(
                provider_id=str(self.id),
                organization_id=str(self.organization_id),
                occurred_at=ts,
            )
        )

    def pop_events(self) -> list[CloudSecurityDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events
