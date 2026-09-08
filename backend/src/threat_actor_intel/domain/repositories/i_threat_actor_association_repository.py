"""IThreatActorAssociationRepository — all methods require `tenant_id`
first, per `exposure.IExposureRecordRepository`'s established
convention (ADR-M51.1-03: associations are always tenant-scoped,
never global)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from threat_actor_intel.domain.aggregates.threat_actor_association import (
        ThreatActorAssociation,
    )
    from threat_actor_intel.domain.value_objects.identifiers import (
        TenantId,
        ThreatActorAssociationId,
        ThreatActorId,
    )


class IThreatActorAssociationRepository(ABC):
    @abstractmethod
    async def save(self, tenant_id: TenantId, association: ThreatActorAssociation) -> None: ...

    @abstractmethod
    async def get(
        self, tenant_id: TenantId, association_id: ThreatActorAssociationId
    ) -> ThreatActorAssociation | None: ...

    @abstractmethod
    async def list_for_tenant(
        self, tenant_id: TenantId, threat_actor_id: ThreatActorId | None = None
    ) -> list[ThreatActorAssociation]: ...
