"""IDiscoveryRegistry — the Resource Discovery framework's own
tenant-isolated store of `CloudDiscoveryJob` aggregates (M45E),
mirroring `IProviderRegistry` (M45C) and `ICredentialReferenceRegistry`
(M45D): the registry *is* the framework's in-memory store, not a
plug-in resolver. Provider-plugin resolution (`IDiscoveryProvider`)
is a separate, deliberately non-tenant-scoped concern — a discovery
provider implementation is shared code, not per-tenant data, the same
precedent `ICloudProviderRegistry` (M45A) and
`IAssetInventoryRegistry` (M45B) already set.
`InMemoryDiscoveryJobRegistry` (M45E) is this milestone's one concrete
implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.domain.aggregates.cloud_discovery_job import CloudDiscoveryJob
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        DiscoveryJobId,
        ProviderId,
        TenantId,
    )


class IDiscoveryRegistry(Protocol):
    def register(self, job: CloudDiscoveryJob) -> None:
        """Raises `DuplicateDiscoveryJobError` if the same
        `(tenant_id, account_id, provider_id)` already has an
        `IN_PROGRESS` job."""
        ...

    def get(self, tenant_id: TenantId, job_id: DiscoveryJobId) -> CloudDiscoveryJob | None: ...

    def list(
        self, tenant_id: TenantId, account_id: AccountId | None = None
    ) -> Sequence[CloudDiscoveryJob]: ...

    def list_active(self, tenant_id: TenantId) -> Sequence[CloudDiscoveryJob]: ...

    def has_active_job(
        self, tenant_id: TenantId, account_id: AccountId, provider_id: ProviderId
    ) -> bool: ...

    def release(self, job: CloudDiscoveryJob) -> None:
        """Free the `(tenant, account, provider)` uniqueness slot once
        `job` has reached a terminal status, so a fresh discovery run
        for the same pair can proceed. A no-op while still
        `IN_PROGRESS`."""
        ...
