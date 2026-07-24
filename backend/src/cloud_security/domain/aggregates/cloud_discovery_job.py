"""CloudDiscoveryJob aggregate — one discovery run against one
`CloudAccount` via one `CloudProviderRegistration` (M45E).

Owns lifecycle, progress, timestamps, discovered/updated/failed
counts, and completion state only — no provider logic (it never calls
a cloud SDK itself), no security evaluation, no risk scoring, no
findings. Referencing `CloudAccount`/`CloudProviderRegistration` by id
only, never by object reference — the same cross-aggregate discipline
every other `cloud_security` aggregate follows. Which specific assets
a run touched is tracked here only as a list of opaque asset-id
strings, for traceability — the assets themselves are owned
exclusively by `CloudAsset` (M45B); this aggregate never holds asset
data."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_security.domain.events.discovery_job_events import (
    DiscoveryJobCancelled,
    DiscoveryJobCompleted,
    DiscoveryJobFailed,
    DiscoveryJobStarted,
)
from cloud_security.domain.exceptions.domain_exceptions import (
    InvalidDiscoveryJobTransition,
    TenantMismatch,
)
from cloud_security.domain.value_objects.enums import DiscoveryJobStatus

if TYPE_CHECKING:
    from datetime import datetime

    from cloud_security.domain.events.base import BaseDomainEvent
    from cloud_security.domain.value_objects.discovery_window import DiscoveryWindow
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        DiscoveryJobId,
        ProviderId,
        TenantId,
    )

_TERMINATE_FROM = {DiscoveryJobStatus.IN_PROGRESS}


class CloudDiscoveryJob:
    __slots__ = (
        "_pending_events",
        "account_id",
        "cancelled_at",
        "completed_at",
        "discovered_asset_ids",
        "discovered_count",
        "failed_count",
        "failure_reason",
        "job_id",
        "provider_id",
        "started_at",
        "status",
        "tenant_id",
        "updated_count",
        "window",
    )

    def __init__(
        self,
        job_id: DiscoveryJobId,
        tenant_id: TenantId,
        account_id: AccountId,
        provider_id: ProviderId,
        window: DiscoveryWindow,
        status: DiscoveryJobStatus,
        started_at: datetime,
        discovered_count: int = 0,
        updated_count: int = 0,
        failed_count: int = 0,
        discovered_asset_ids: tuple[str, ...] = (),
        completed_at: datetime | None = None,
        cancelled_at: datetime | None = None,
        failure_reason: str | None = None,
    ) -> None:
        self.job_id = job_id
        self.tenant_id = tenant_id
        self.account_id = account_id
        self.provider_id = provider_id
        self.window = window
        self.status = status
        self.started_at = started_at
        self.discovered_count = discovered_count
        self.updated_count = updated_count
        self.failed_count = failed_count
        self.discovered_asset_ids = discovered_asset_ids
        self.completed_at = completed_at
        self.cancelled_at = cancelled_at
        self.failure_reason = failure_reason
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

    def _assert_in_progress(self, to_status: str) -> None:
        if self.status not in _TERMINATE_FROM:
            raise InvalidDiscoveryJobTransition(self.status.value, to_status)

    @classmethod
    def start(
        cls,
        job_id: DiscoveryJobId,
        tenant_id: TenantId,
        account_id: AccountId,
        provider_id: ProviderId,
        window: DiscoveryWindow,
        now: datetime,
    ) -> CloudDiscoveryJob:
        job = cls(
            job_id=job_id,
            tenant_id=tenant_id,
            account_id=account_id,
            provider_id=provider_id,
            window=window,
            status=DiscoveryJobStatus.IN_PROGRESS,
            started_at=now,
        )
        job._emit(
            DiscoveryJobStarted(
                tenant_id=str(tenant_id),
                aggregate_id=str(job_id),
                aggregate_type="CloudDiscoveryJob",
                occurred_at=now,
                account_id=str(account_id),
                provider_id=str(provider_id),
            )
        )
        return job

    def record_discovered_asset(self, tenant_id: TenantId, asset_id: str, updated: bool) -> None:
        self._assert_tenant(tenant_id)
        self._assert_in_progress("progress recorded")
        self.discovered_asset_ids = (*self.discovered_asset_ids, asset_id)
        if updated:
            self.updated_count += 1
        else:
            self.discovered_count += 1

    def record_failure(self, tenant_id: TenantId) -> None:
        self._assert_tenant(tenant_id)
        self._assert_in_progress("progress recorded")
        self.failed_count += 1

    def complete(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._assert_in_progress(DiscoveryJobStatus.COMPLETED.value)
        self.status = DiscoveryJobStatus.COMPLETED
        self.completed_at = now
        self._emit(
            DiscoveryJobCompleted(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.job_id),
                aggregate_type="CloudDiscoveryJob",
                occurred_at=now,
                discovered_count=self.discovered_count,
                updated_count=self.updated_count,
                failed_count=self.failed_count,
            )
        )

    def fail(self, tenant_id: TenantId, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._assert_in_progress(DiscoveryJobStatus.FAILED.value)
        self.status = DiscoveryJobStatus.FAILED
        self.completed_at = now
        self.failure_reason = reason
        self._emit(
            DiscoveryJobFailed(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.job_id),
                aggregate_type="CloudDiscoveryJob",
                occurred_at=now,
                reason=reason,
            )
        )

    def cancel(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._assert_in_progress(DiscoveryJobStatus.CANCELLED.value)
        self.status = DiscoveryJobStatus.CANCELLED
        self.cancelled_at = now
        self._emit(
            DiscoveryJobCancelled(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.job_id),
                aggregate_type="CloudDiscoveryJob",
                occurred_at=now,
            )
        )
