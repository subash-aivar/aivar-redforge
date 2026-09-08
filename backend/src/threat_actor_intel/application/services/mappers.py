"""Aggregate -> DTO mappers for threat_actor_intel (M51.1 Phase 2),
mirroring `exposure.application.services.mappers`'s convention."""

from __future__ import annotations

from typing import TYPE_CHECKING

from threat_actor_intel.application.dtos.threat_actor_dtos import (
    ThreatActorAssociationDTO,
    ThreatActorDetailDTO,
    ThreatActorSummaryDTO,
)

if TYPE_CHECKING:
    from threat_actor_intel.domain.aggregates.threat_actor import ThreatActor
    from threat_actor_intel.domain.aggregates.threat_actor_association import (
        ThreatActorAssociation,
    )


def to_summary_dto(actor: ThreatActor) -> ThreatActorSummaryDTO:
    return ThreatActorSummaryDTO(
        threat_actor_id=str(actor.threat_actor_id),
        tenant_id=str(actor.tenant_id) if actor.tenant_id is not None else None,
        name=str(actor.name),
        origin=actor.origin.value,
        status=actor.status.value,
        attribution_confidence=actor.attribution_confidence.value,
    )


def to_detail_dto(actor: ThreatActor) -> ThreatActorDetailDTO:
    return ThreatActorDetailDTO(
        threat_actor_id=str(actor.threat_actor_id),
        tenant_id=str(actor.tenant_id) if actor.tenant_id is not None else None,
        name=str(actor.name),
        origin=actor.origin.value,
        status=actor.status.value,
        attribution_confidence=actor.attribution_confidence.value,
        sophistication=actor.sophistication.value,
        motivations=tuple(sorted(m.value for m in actor.motivations)),
        aliases=tuple(str(a) for a in actor.aliases),
        technique_refs=tuple(ref.technique_id for ref in actor.technique_refs),
        indicator_refs=tuple(ref.indicator_id for ref in actor.indicator_refs),
        created_at=actor.created_at.isoformat(),
        updated_at=actor.updated_at.isoformat(),
    )


def to_association_dto(association: ThreatActorAssociation) -> ThreatActorAssociationDTO:
    return ThreatActorAssociationDTO(
        association_id=str(association.association_id),
        tenant_id=str(association.tenant_id),
        threat_actor_id=str(association.threat_actor_id),
        referenced_entity_type=association.referenced_entity.entity_type,
        referenced_entity_id=association.referenced_entity.entity_id,
        evidence_citation=str(association.evidence_citation),
        state=association.state.value,
        created_at=association.created_at.isoformat(),
        retracted_at=association.retracted_at.isoformat() if association.retracted_at else None,
    )
