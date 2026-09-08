"""Application DTOs for attack_pattern_intel (M51.3 Phase B1). Frozen,
primitive-typed dataclasses only — no domain value objects or
aggregate references ever cross this boundary, mirroring
`ioc_intelligence.application.dtos.ioc_dtos`'s convention."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class SourceAttributionDTO:
    source_system: str
    reference: str
    observed_at: str
    notes: str = ""


@dataclass(frozen=True, slots=True)
class TacticMappingDTO:
    tactic_id: str
    tactic_shortname: str
    priority: int = 0
    notes: str = ""


@dataclass(frozen=True, slots=True)
class DetectionGuidanceDTO:
    content: str
    attribution: SourceAttributionDTO


@dataclass(frozen=True, slots=True)
class MitigationReferenceDTO:
    mitigation_id: str
    name: str
    description: str
    attribution: SourceAttributionDTO


@dataclass(frozen=True, slots=True)
class ProcedureExampleDTO:
    description: str
    attribution: SourceAttributionDTO
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class RelationshipMetadataDTO:
    relationship_type: str
    target_attack_pattern_id: str
    attribution: SourceAttributionDTO


@dataclass(frozen=True, slots=True)
class VersionRecordDTO:
    version: int
    changed_at: str
    change_summary: str
    source: str


@dataclass(frozen=True, slots=True)
class AttackPatternSummaryDTO:
    attack_pattern_id: str
    tenant_id: str | None
    technique_id: str
    sub_technique_id: str | None
    lifecycle_status: str
    created_at: str
    updated_at: str
    guidance_count: int = 0
    mitigation_count: int = 0
    procedure_example_count: int = 0


@dataclass(frozen=True, slots=True)
class AttackPatternDetailDTO:
    attack_pattern_id: str
    tenant_id: str | None
    technique_id: str
    sub_technique_id: str | None
    lifecycle_status: str
    superseded_by: str | None
    created_at: str
    updated_at: str
    tactic_mappings: tuple[TacticMappingDTO, ...] = field(default_factory=tuple)
    platforms: tuple[str, ...] = field(default_factory=tuple)
    detection_guidance: tuple[DetectionGuidanceDTO, ...] = field(default_factory=tuple)
    mitigation_references: tuple[MitigationReferenceDTO, ...] = field(default_factory=tuple)
    procedure_examples: tuple[ProcedureExampleDTO, ...] = field(default_factory=tuple)
    relationship_metadata: tuple[RelationshipMetadataDTO, ...] = field(default_factory=tuple)
    version_history: tuple[VersionRecordDTO, ...] = field(default_factory=tuple)
