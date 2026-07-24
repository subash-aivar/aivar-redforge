"""IDiscoveryReader — the read-side extension point for a future
persistence-backed discovery-job store (M45E), mirroring `IAssetReader`
(M45B) and `ICredentialReferenceReader` (M45D). No concrete
implementation exists in this milestone — `InMemoryDiscoveryJobRegistry`
serves reads directly this milestone; this port exists for a future
infrastructure milestone to swap in real storage without changing the
application service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.application.dtos.discovery_job_record import DiscoveryJobRecord
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        DiscoveryJobId,
        TenantId,
    )


class IDiscoveryReader(Protocol):
    def get(self, tenant_id: TenantId, job_id: DiscoveryJobId) -> DiscoveryJobRecord | None: ...

    def list(
        self, tenant_id: TenantId, account_id: AccountId | None = None
    ) -> Sequence[DiscoveryJobRecord]: ...
