"""CloudAccount aggregate — the tenant's registered connection to one
cloud platform account (an AWS account, an Azure subscription, a GCP
project), its connection lifecycle, its linked credential reference,
and its discovery lifecycle (M45A).

Deliberately the aggregate boundary for connection/discovery state:
`CloudAsset` (a separate aggregate) holds the resources *found* by a
completed discovery run, not the run's own lifecycle."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_security.domain.events.cloud_account_events import (
    CloudAccountRegistered,
    CredentialLinked,
    DiscoveryCompleted,
)
from cloud_security.domain.exceptions.domain_exceptions import (
    CredentialAlreadyLinkedError,
    EmptyDisplayNameError,
    InvalidCloudAccountTransition,
    InvalidDiscoveryTransition,
    TenantMismatch,
)
from cloud_security.domain.value_objects.enums import CloudConnectionStatus, CloudDiscoveryState

if TYPE_CHECKING:
    from datetime import datetime

    from cloud_security.domain.events.base import BaseDomainEvent
    from cloud_security.domain.value_objects.cloud_credential_reference import (
        CloudCredentialReference,
    )
    from cloud_security.domain.value_objects.cloud_tag import CloudTagSet
    from cloud_security.domain.value_objects.enums import CloudPlatformType
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        ProviderId,
        TenantId,
    )

_CONNECT_FROM = {CloudConnectionStatus.PENDING, CloudConnectionStatus.DISCONNECTED}
_DISCONNECT_FROM = {CloudConnectionStatus.CONNECTED}
_REVOKE_FROM = {
    CloudConnectionStatus.PENDING,
    CloudConnectionStatus.CONNECTED,
    CloudConnectionStatus.DISCONNECTED,
    CloudConnectionStatus.ERROR,
}
_START_DISCOVERY_FROM = {
    CloudDiscoveryState.NOT_STARTED,
    CloudDiscoveryState.FAILED,
    # M45E: a previously COMPLETED account must be re-discoverable
    # (refresh/re-scan) — discovery is not a one-shot operation.
    CloudDiscoveryState.COMPLETED,
}
_COMPLETE_DISCOVERY_FROM = {CloudDiscoveryState.IN_PROGRESS}
_FAIL_DISCOVERY_FROM = {CloudDiscoveryState.IN_PROGRESS}


class CloudAccount:
    __slots__ = (
        "_pending_events",
        "account_id",
        "connection_status",
        "credential_ref",
        "discovery_state",
        "display_name",
        "platform_type",
        "provider_id",
        "registered_at",
        "tags",
        "tenant_id",
    )

    def __init__(
        self,
        account_id: AccountId,
        tenant_id: TenantId,
        provider_id: ProviderId,
        platform_type: CloudPlatformType,
        display_name: str,
        connection_status: CloudConnectionStatus,
        discovery_state: CloudDiscoveryState,
        registered_at: datetime,
        tags: CloudTagSet,
        credential_ref: CloudCredentialReference | None = None,
    ) -> None:
        self.account_id = account_id
        self.tenant_id = tenant_id
        self.provider_id = provider_id
        self.platform_type = platform_type
        self.display_name = display_name
        self.connection_status = connection_status
        self.discovery_state = discovery_state
        self.registered_at = registered_at
        self.tags = tags
        self.credential_ref = credential_ref
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

    @classmethod
    def register(
        cls,
        account_id: AccountId,
        tenant_id: TenantId,
        provider_id: ProviderId,
        platform_type: CloudPlatformType,
        display_name: str,
        tags: CloudTagSet,
        now: datetime,
    ) -> CloudAccount:
        if not display_name.strip():
            raise EmptyDisplayNameError()
        account = cls(
            account_id=account_id,
            tenant_id=tenant_id,
            provider_id=provider_id,
            platform_type=platform_type,
            display_name=display_name,
            connection_status=CloudConnectionStatus.PENDING,
            discovery_state=CloudDiscoveryState.NOT_STARTED,
            registered_at=now,
            tags=tags,
        )
        account._emit(
            CloudAccountRegistered(
                tenant_id=str(tenant_id),
                aggregate_id=str(account_id),
                aggregate_type="CloudAccount",
                occurred_at=now,
                platform_type=platform_type,
                display_name=display_name,
            )
        )
        return account

    def link_credential(
        self, tenant_id: TenantId, credential_ref: CloudCredentialReference, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.credential_ref is not None:
            raise CredentialAlreadyLinkedError()
        self.credential_ref = credential_ref
        self._emit(
            CredentialLinked(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.account_id),
                aggregate_type="CloudAccount",
                occurred_at=now,
                credential_type=credential_ref.credential_type,
            )
        )

    def mark_connected(self, tenant_id: TenantId) -> None:
        self._assert_tenant(tenant_id)
        if self.connection_status not in _CONNECT_FROM:
            raise InvalidCloudAccountTransition(
                self.connection_status.value, CloudConnectionStatus.CONNECTED.value
            )
        self.connection_status = CloudConnectionStatus.CONNECTED

    def mark_disconnected(self, tenant_id: TenantId) -> None:
        self._assert_tenant(tenant_id)
        if self.connection_status not in _DISCONNECT_FROM:
            raise InvalidCloudAccountTransition(
                self.connection_status.value, CloudConnectionStatus.DISCONNECTED.value
            )
        self.connection_status = CloudConnectionStatus.DISCONNECTED

    def mark_error(self, tenant_id: TenantId) -> None:
        self._assert_tenant(tenant_id)
        self.connection_status = CloudConnectionStatus.ERROR

    def revoke(self, tenant_id: TenantId) -> None:
        self._assert_tenant(tenant_id)
        if self.connection_status not in _REVOKE_FROM:
            raise InvalidCloudAccountTransition(
                self.connection_status.value, CloudConnectionStatus.REVOKED.value
            )
        self.connection_status = CloudConnectionStatus.REVOKED

    def start_discovery(self, tenant_id: TenantId) -> None:
        self._assert_tenant(tenant_id)
        if self.discovery_state not in _START_DISCOVERY_FROM:
            raise InvalidDiscoveryTransition(
                self.discovery_state.value, CloudDiscoveryState.IN_PROGRESS.value
            )
        self.discovery_state = CloudDiscoveryState.IN_PROGRESS

    def complete_discovery(
        self, tenant_id: TenantId, discovered_asset_count: int, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.discovery_state not in _COMPLETE_DISCOVERY_FROM:
            raise InvalidDiscoveryTransition(
                self.discovery_state.value, CloudDiscoveryState.COMPLETED.value
            )
        if discovered_asset_count < 0:
            raise ValueError("discovered_asset_count must be >= 0")
        self.discovery_state = CloudDiscoveryState.COMPLETED
        self._emit(
            DiscoveryCompleted(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.account_id),
                aggregate_type="CloudAccount",
                occurred_at=now,
                discovered_asset_count=discovered_asset_count,
            )
        )

    def fail_discovery(self, tenant_id: TenantId) -> None:
        self._assert_tenant(tenant_id)
        if self.discovery_state not in _FAIL_DISCOVERY_FROM:
            raise InvalidDiscoveryTransition(
                self.discovery_state.value, CloudDiscoveryState.FAILED.value
            )
        self.discovery_state = CloudDiscoveryState.FAILED
