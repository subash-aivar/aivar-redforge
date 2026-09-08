"""Application DTOs for intelligence_relationships (M51.4 Phase C1).
Frozen, primitive-typed dataclasses only — no domain value objects or
aggregate references ever cross this boundary, mirroring
`attack_pattern_intel.application.dtos.attack_pattern_dtos`'s
convention."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class SourceAttributionDTO:
    source_system: str
    reference: str
    observed_at: str
    confidence: str
    notes: str = ""


@dataclass(frozen=True, slots=True)
class EvidenceCitationDTO:
    value: str


@dataclass(frozen=True, slots=True)
class EntityRefDTO:
    entity_type: str
    entity_id: str


@dataclass(frozen=True, slots=True)
class VersionRecordDTO:
    version: int
    changed_at: str
    change_summary: str
    source: str


@dataclass(frozen=True, slots=True)
class RelationshipSummaryDTO:
    relationship_id: str
    tenant_id: str | None
    relationship_type: str
    source_entity: EntityRefDTO
    target_entity: EntityRefDTO
    direction: str
    confidence: str
    epistemic_state: str
    lifecycle_status: str
    created_at: str
    updated_at: str
    evidence_citation_count: int = 0
    source_attribution_count: int = 0


@dataclass(frozen=True, slots=True)
class RelationshipDetailDTO:
    relationship_id: str
    tenant_id: str | None
    relationship_type: str
    source_entity: EntityRefDTO
    target_entity: EntityRefDTO
    direction: str
    confidence: str
    epistemic_state: str
    lifecycle_status: str
    superseded_by: str | None
    valid_from: str
    valid_until: str | None
    created_at: str
    updated_at: str
    evidence_citations: tuple[EvidenceCitationDTO, ...] = field(default_factory=tuple)
    source_attributions: tuple[SourceAttributionDTO, ...] = field(default_factory=tuple)
    version_history: tuple[VersionRecordDTO, ...] = field(default_factory=tuple)
