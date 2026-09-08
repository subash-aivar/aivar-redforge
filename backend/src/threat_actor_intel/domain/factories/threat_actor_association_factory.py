"""ThreatActorAssociationFactory — the recommended way to construct a
`ThreatActorAssociation` (M51.1). Delegates entirely to
`ThreatActorAssociation.create`, mirroring `ThreatActorFactory`'s own
split of "who is allowed to construct" vs "what must be true to
exist"."""

from __future__ import annotations

from typing import TYPE_CHECKING

from threat_actor_intel.domain.aggregates.threat_actor_association import ThreatActorAssociation
from threat_actor_intel.domain.value_objects.identifiers import ThreatActorAssociationId

if TYPE_CHECKING:
    from datetime import datetime

    from threat_actor_intel.domain.value_objects.evidence import EvidenceCitation
    from threat_actor_intel.domain.value_objects.identifiers import TenantId, ThreatActorId
    from threat_actor_intel.domain.value_objects.references import ReferencedEntityRef


class ThreatActorAssociationFactory:
    @staticmethod
    def create(
        tenant_id: TenantId,
        threat_actor_id: ThreatActorId,
        referenced_entity: ReferencedEntityRef,
        evidence_citation: EvidenceCitation,
        now: datetime,
        association_id: ThreatActorAssociationId | None = None,
    ) -> ThreatActorAssociation:
        resolved_id = association_id or ThreatActorAssociationId.generate()
        return ThreatActorAssociation.create(
            association_id=resolved_id,
            tenant_id=tenant_id,
            threat_actor_id=threat_actor_id,
            referenced_entity=referenced_entity,
            evidence_citation=evidence_citation,
            now=now,
        )
