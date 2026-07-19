"""CloudAccount aggregate root."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from redforge.domain.cloud_security.entities import CloudRegion
from redforge.domain.cloud_security.events import (
    CloudAccountCredentialRotated,
    CloudAccountDiscovered,
    CloudAccountSyncCompleted,
    CloudAccountSyncFailed,
    CloudAccountSyncStarted,
    CloudSecurityDomainEvent,
)
from redforge.domain.cloud_security.exceptions import InvalidCloudArgumentError
from redforge.domain.cloud_security.value_objects import (
    AccountSyncState,
    CloudAccountId,
    CloudAccountMetadata,
    CloudAccountType,
    CloudProviderId,
    CredentialRef,
    OrganizationId,
    SyncStatus,
)


@dataclass
class CloudAccount:
    id: CloudAccountId
    cloud_provider_id: CloudProviderId
    organization_id: OrganizationId
    external_id: str
    display_name: str
    account_type: CloudAccountType
    regions: tuple[CloudRegion, ...]
    credential_ref: CredentialRef
    sync_state: AccountSyncState
    metadata: CloudAccountMetadata
    tags: dict[str, str]
    created_at: datetime
    updated_at: datetime
    version: int = 1
    _pending_events: list[CloudSecurityDomainEvent] = field(default_factory=list, repr=False)

    @classmethod
    def register(
        cls,
        *,
        cloud_provider_id: CloudProviderId,
        organization_id: OrganizationId,
        external_id: str,
        display_name: str,
        account_type: CloudAccountType,
        credential_ref: CredentialRef,
        regions: tuple[CloudRegion, ...] = (),
        metadata: CloudAccountMetadata | None = None,
        tags: dict[str, str] | None = None,
        now: datetime | None = None,
        account_id: CloudAccountId | None = None,
    ) -> CloudAccount:
        ext = external_id.strip() if external_id else ""
        if not ext:
            raise InvalidCloudArgumentError("external_id", "required")
        if len(ext) > 256:
            raise InvalidCloudArgumentError("external_id", "max 256 chars")
        name = display_name.strip() if display_name else ""
        if not name:
            raise InvalidCloudArgumentError("display_name", "required")
        if len(name) > 256:
            raise InvalidCloudArgumentError("display_name", "max 256 chars")
        tag_map = dict(tags or {})
        if len(tag_map) > 100:
            raise InvalidCloudArgumentError("tags", "max 100 entries")
        for key, value in tag_map.items():
            if len(key) > 128 or len(value) > 512:
                raise InvalidCloudArgumentError("tags", "key/value length exceeded")
        ts = now or datetime.now(UTC)
        aggregate = cls(
            id=account_id or CloudAccountId.generate(),
            cloud_provider_id=cloud_provider_id,
            organization_id=organization_id,
            external_id=ext,
            display_name=name,
            account_type=account_type,
            regions=regions,
            credential_ref=credential_ref,
            sync_state=AccountSyncState.pending(),
            metadata=metadata or CloudAccountMetadata(),
            tags=tag_map,
            created_at=ts,
            updated_at=ts,
            version=1,
        )
        aggregate._pending_events.append(
            CloudAccountDiscovered(
                account_id=str(aggregate.id),
                cloud_provider_id=str(cloud_provider_id),
                organization_id=str(organization_id),
                external_id=ext,
                account_type=account_type.value,
                occurred_at=ts,
            )
        )
        return aggregate

    def mark_sync_started(self, *, now: datetime | None = None) -> None:
        ts = now or datetime.now(UTC)
        self.sync_state = AccountSyncState(
            status=SyncStatus.SYNCING,
            last_sync_started_at=ts,
            last_sync_completed_at=self.sync_state.last_sync_completed_at,
            last_error=None,
        )
        self.updated_at = ts
        self.version += 1
        self._pending_events.append(
            CloudAccountSyncStarted(
                account_id=str(self.id),
                organization_id=str(self.organization_id),
                occurred_at=ts,
            )
        )

    def mark_sync_completed(self, *, now: datetime | None = None) -> None:
        ts = now or datetime.now(UTC)
        self.sync_state = AccountSyncState(
            status=SyncStatus.SYNCED,
            last_sync_started_at=self.sync_state.last_sync_started_at,
            last_sync_completed_at=ts,
            last_error=None,
        )
        self.updated_at = ts
        self.version += 1
        self._pending_events.append(
            CloudAccountSyncCompleted(
                account_id=str(self.id),
                organization_id=str(self.organization_id),
                occurred_at=ts,
            )
        )

    def mark_sync_failed(self, error: str, *, now: datetime | None = None) -> None:
        if not error or not error.strip():
            raise InvalidCloudArgumentError("error", "required for FAILED sync")
        ts = now or datetime.now(UTC)
        self.sync_state = AccountSyncState(
            status=SyncStatus.FAILED,
            last_sync_started_at=self.sync_state.last_sync_started_at,
            last_sync_completed_at=self.sync_state.last_sync_completed_at,
            last_error=error.strip()[:4000],
        )
        self.updated_at = ts
        self.version += 1
        self._pending_events.append(
            CloudAccountSyncFailed(
                account_id=str(self.id),
                organization_id=str(self.organization_id),
                error=self.sync_state.last_error or error,
                occurred_at=ts,
            )
        )

    def rotate_credential(
        self, credential_ref: CredentialRef, *, now: datetime | None = None
    ) -> None:
        ts = now or datetime.now(UTC)
        self.credential_ref = credential_ref
        self.updated_at = ts
        self.version += 1
        self._pending_events.append(
            CloudAccountCredentialRotated(
                account_id=str(self.id),
                organization_id=str(self.organization_id),
                credential_reference_id=credential_ref.reference_id,
                occurred_at=ts,
            )
        )

    def pop_events(self) -> list[CloudSecurityDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events
