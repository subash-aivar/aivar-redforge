"""InMemoryDiscoveryJobRegistry — the one concrete registry this
milestone implements (M45E). Stores `CloudDiscoveryJob` aggregates
in-memory, keyed by `job_id`, with a secondary uniqueness constraint
of one *active* (`IN_PROGRESS`) job per `(tenant_id, account_id,
provider_id)`. No persistence, no DI container wiring, no cloud SDK
calls."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_security.application.exceptions import DuplicateDiscoveryJobError
from cloud_security.domain.value_objects.enums import DiscoveryJobStatus

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.domain.aggregates.cloud_discovery_job import CloudDiscoveryJob
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        DiscoveryJobId,
        ProviderId,
        TenantId,
    )


class InMemoryDiscoveryJobRegistry:
    def __init__(self) -> None:
        self._by_job_id: dict[str, CloudDiscoveryJob] = {}
        self._active_by_tenant_account_provider: dict[tuple[str, str, str], str] = {}

    def register(self, job: CloudDiscoveryJob) -> None:
        key = (str(job.tenant_id), str(job.account_id), str(job.provider_id))
        if key in self._active_by_tenant_account_provider:
            raise DuplicateDiscoveryJobError(job.account_id, job.provider_id)
        self._by_job_id[str(job.job_id)] = job
        self._active_by_tenant_account_provider[key] = str(job.job_id)

    def get(self, tenant_id: TenantId, job_id: DiscoveryJobId) -> CloudDiscoveryJob | None:
        job = self._by_job_id.get(str(job_id))
        if job is None or job.tenant_id != tenant_id:
            return None
        return job

    def list(
        self, tenant_id: TenantId, account_id: AccountId | None = None
    ) -> Sequence[CloudDiscoveryJob]:
        results = (j for j in self._by_job_id.values() if j.tenant_id == tenant_id)
        if account_id is not None:
            results = (j for j in results if j.account_id == account_id)
        return tuple(results)

    def list_active(self, tenant_id: TenantId) -> Sequence[CloudDiscoveryJob]:
        return tuple(
            j
            for j in self._by_job_id.values()
            if j.tenant_id == tenant_id and j.status == DiscoveryJobStatus.IN_PROGRESS
        )

    def has_active_job(
        self, tenant_id: TenantId, account_id: AccountId, provider_id: ProviderId
    ) -> bool:
        return (str(tenant_id), str(account_id), str(provider_id)) in (
            self._active_by_tenant_account_provider
        )

    def release(self, job: CloudDiscoveryJob) -> None:
        if job.status == DiscoveryJobStatus.IN_PROGRESS:
            return
        key = (str(job.tenant_id), str(job.account_id), str(job.provider_id))
        self._active_by_tenant_account_provider.pop(key, None)
