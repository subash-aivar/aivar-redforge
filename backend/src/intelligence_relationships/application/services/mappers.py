"""Aggregate -> DTO mappers for intelligence_relationships (M51.4
Phase C1)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from intelligence_relationships.application.dtos.relationship_dtos import (
    EntityRefDTO,
    EvidenceCitationDTO,
    RelationshipDetailDTO,
    RelationshipSummaryDTO,
    SourceAttributionDTO,
    VersionRecordDTO,
)

if TYPE_CHECKING:
    from intelligence_relationships.domain.aggregates.intelligence_relationship import (
        IntelligenceRelationship,
    )
    from intelligence_relationships.domain.value_objects.entity_ref import EntityRef
    from intelligence_relationships.domain.value_objects.evidence import SourceAttribution


def _entity_ref_dto(ref: EntityRef) -> EntityRefDTO:
    return EntityRefDTO(entity_type=ref.entity_type.value, entity_id=ref.entity_id)


def _attribution_dto(attribution: SourceAttribution) -> SourceAttributionDTO:
    return SourceAttributionDTO(
        source_system=attribution.source_system,
        reference=attribution.reference,
        observed_at=attribution.observed_at.isoformat(),
        confidence=attribution.confidence.value,
        notes=attribution.notes,
    )


def to_summary_dto(relationship: IntelligenceRelationship) -> RelationshipSummaryDTO:
    return RelationshipSummaryDTO(
        relationship_id=str(relationship.relationship_id),
        tenant_id=str(relationship.tenant_id) if relationship.tenant_id is not None else None,
        relationship_type=relationship.relationship_type.value,
        source_entity=_entity_ref_dto(relationship.source_entity),
        target_entity=_entity_ref_dto(relationship.target_entity),
        direction=relationship.direction.value,
        confidence=relationship.confidence.value,
        epistemic_state=relationship.epistemic_state.value,
        lifecycle_status=relationship.lifecycle_status.value,
        created_at=relationship.created_at.isoformat(),
        updated_at=relationship.updated_at.isoformat(),
        evidence_citation_count=len(relationship.evidence_citations),
        source_attribution_count=len(relationship.source_attributions),
    )


def to_detail_dto(relationship: IntelligenceRelationship) -> RelationshipDetailDTO:
    return RelationshipDetailDTO(
        relationship_id=str(relationship.relationship_id),
        tenant_id=str(relationship.tenant_id) if relationship.tenant_id is not None else None,
        relationship_type=relationship.relationship_type.value,
        source_entity=_entity_ref_dto(relationship.source_entity),
        target_entity=_entity_ref_dto(relationship.target_entity),
        direction=relationship.direction.value,
        confidence=relationship.confidence.value,
        epistemic_state=relationship.epistemic_state.value,
        lifecycle_status=relationship.lifecycle_status.value,
        superseded_by=(
            str(relationship.superseded_by) if relationship.superseded_by is not None else None
        ),
        valid_from=relationship.validity.valid_from.isoformat(),
        valid_until=(
            relationship.validity.valid_until.isoformat()
            if relationship.validity.valid_until is not None
            else None
        ),
        created_at=relationship.created_at.isoformat(),
        updated_at=relationship.updated_at.isoformat(),
        evidence_citations=tuple(
            EvidenceCitationDTO(value=c.value) for c in relationship.evidence_citations
        ),
        source_attributions=tuple(_attribution_dto(a) for a in relationship.source_attributions),
        version_history=tuple(
            VersionRecordDTO(
                version=v.version,
                changed_at=v.changed_at.isoformat(),
                change_summary=v.change_summary,
                source=v.source,
            )
            for v in relationship.version_history
        ),
    )
