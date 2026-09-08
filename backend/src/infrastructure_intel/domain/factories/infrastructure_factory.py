"""InfrastructureFactory — the single supported construction path for
`Infrastructure` aggregates.

Stays pure/sync: it performs no I/O and calls no port. It normalizes
`normalized_identifier` per `infrastructure_type` (see
`normalize_identifier`) so callers may hand it raw analyst input.
Scope-level uniqueness of `(infrastructure_type,
normalized_identifier)` must already have been checked by the
application service (repository existence check) BEFORE this factory is
invoked — mirroring `tool_intel`'s exact factory-stays-pure discipline.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from infrastructure_intel.domain.aggregates.infrastructure import Infrastructure
from infrastructure_intel.domain.value_objects.enums import InfrastructureConfidence
from infrastructure_intel.domain.value_objects.identifiers import InfrastructureId
from infrastructure_intel.domain.value_objects.normalized_identifier import (
    normalize_identifier,
)

if TYPE_CHECKING:
    from datetime import datetime

    from infrastructure_intel.domain.value_objects.enums import InfrastructureType
    from infrastructure_intel.domain.value_objects.hosting import (
        CloudProviderRef,
        HostingProviderRef,
        NetworkOwnership,
        Region,
    )
    from infrastructure_intel.domain.value_objects.identifiers import TenantId


class InfrastructureFactory:
    def observe(
        self,
        tenant_id: TenantId | None,
        infrastructure_type: InfrastructureType,
        normalized_identifier: str,
        now: datetime,
        hosting_provider: HostingProviderRef | None = None,
        cloud_provider: CloudProviderRef | None = None,
        regions: tuple[Region, ...] = (),
        network_ownership: NetworkOwnership | None = None,
        confidence: InfrastructureConfidence = InfrastructureConfidence.MEDIUM,
    ) -> Infrastructure:
        return Infrastructure.observe(
            infrastructure_id=InfrastructureId.generate(),
            tenant_id=tenant_id,
            infrastructure_type=infrastructure_type,
            normalized_identifier=normalize_identifier(infrastructure_type, normalized_identifier),
            now=now,
            hosting_provider=hosting_provider,
            cloud_provider=cloud_provider,
            regions=regions,
            network_ownership=network_ownership,
            confidence=confidence,
        )
