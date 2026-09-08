"""Aggregate -> DTO mappers for attack_pattern_intel (M51.3 Phase B1)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from attack_pattern_intel.application.dtos.attack_pattern_dtos import (
    AttackPatternDetailDTO,
    AttackPatternSummaryDTO,
    DetectionGuidanceDTO,
    MitigationReferenceDTO,
    ProcedureExampleDTO,
    RelationshipMetadataDTO,
    SourceAttributionDTO,
    TacticMappingDTO,
    VersionRecordDTO,
)

if TYPE_CHECKING:
    from attack_pattern_intel.domain.aggregates.attack_pattern import AttackPattern
    from attack_pattern_intel.domain.value_objects.evidence import SourceAttribution


def _attribution_dto(attribution: SourceAttribution) -> SourceAttributionDTO:
    return SourceAttributionDTO(
        source_system=attribution.source_system,
        reference=attribution.reference,
        observed_at=attribution.observed_at.isoformat(),
        notes=attribution.notes,
    )


def to_summary_dto(pattern: AttackPattern) -> AttackPatternSummaryDTO:
    ref = pattern.mitre_technique_ref
    return AttackPatternSummaryDTO(
        attack_pattern_id=str(pattern.attack_pattern_id),
        tenant_id=str(pattern.tenant_id) if pattern.tenant_id is not None else None,
        technique_id=ref.technique_id,
        sub_technique_id=ref.sub_technique_id,
        lifecycle_status=pattern.lifecycle_status.value,
        created_at=pattern.created_at.isoformat(),
        updated_at=pattern.updated_at.isoformat(),
        guidance_count=len(pattern.detection_guidance),
        mitigation_count=len(pattern.mitigation_references),
        procedure_example_count=len(pattern.procedure_examples),
    )


def to_detail_dto(pattern: AttackPattern) -> AttackPatternDetailDTO:
    ref = pattern.mitre_technique_ref
    return AttackPatternDetailDTO(
        attack_pattern_id=str(pattern.attack_pattern_id),
        tenant_id=str(pattern.tenant_id) if pattern.tenant_id is not None else None,
        technique_id=ref.technique_id,
        sub_technique_id=ref.sub_technique_id,
        lifecycle_status=pattern.lifecycle_status.value,
        superseded_by=str(pattern.superseded_by) if pattern.superseded_by is not None else None,
        created_at=pattern.created_at.isoformat(),
        updated_at=pattern.updated_at.isoformat(),
        tactic_mappings=tuple(
            TacticMappingDTO(
                tactic_id=t.tactic_id,
                tactic_shortname=t.tactic_shortname,
                priority=t.priority,
                notes=t.notes,
            )
            for t in pattern.tactic_mappings
        ),
        platforms=pattern.platforms,
        detection_guidance=tuple(
            DetectionGuidanceDTO(content=g.content, attribution=_attribution_dto(g.attribution))
            for g in pattern.detection_guidance
        ),
        mitigation_references=tuple(
            MitigationReferenceDTO(
                mitigation_id=m.mitigation_id,
                name=m.name,
                description=m.description,
                attribution=_attribution_dto(m.attribution),
            )
            for m in pattern.mitigation_references
        ),
        procedure_examples=tuple(
            ProcedureExampleDTO(
                description=p.description,
                attribution=_attribution_dto(p.attribution),
                actor_ref=p.actor_ref,
            )
            for p in pattern.procedure_examples
        ),
        relationship_metadata=tuple(
            RelationshipMetadataDTO(
                relationship_type=r.relationship_type,
                target_attack_pattern_id=str(r.target_attack_pattern_id),
                attribution=_attribution_dto(r.attribution),
            )
            for r in pattern.relationship_metadata
        ),
        version_history=tuple(
            VersionRecordDTO(
                version=v.version,
                changed_at=v.changed_at.isoformat(),
                change_summary=v.change_summary,
                source=v.source,
            )
            for v in pattern.version_history
        ),
    )
