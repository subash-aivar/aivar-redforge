"""Pydantic request/response schemas for attack_pattern_intel's API
(M51.3 Phase B1) — separate from the application-layer DTOs, mirroring
`ioc_intelligence.api.schemas.ioc_schemas`'s convention."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SourceAttributionRequest(BaseModel):
    source_system: str
    reference: str
    observed_at: str
    notes: str = ""


class TacticMappingRequest(BaseModel):
    tactic_id: str
    tactic_shortname: str
    priority: int = 0
    notes: str = ""


class ObserveAttackPatternRequest(BaseModel):
    technique_id: str
    sub_technique_id: str | None = None
    tactic_mappings: list[TacticMappingRequest] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)


class AddDetectionGuidanceRequest(BaseModel):
    content: str
    attribution: SourceAttributionRequest


class AddMitigationReferenceRequest(BaseModel):
    mitigation_id: str
    name: str
    description: str
    attribution: SourceAttributionRequest


class AddProcedureExampleRequest(BaseModel):
    description: str
    attribution: SourceAttributionRequest
    actor_ref: str | None = None


class AddRelationshipRequest(BaseModel):
    relationship_type: str
    target_attack_pattern_id: str
    attribution: SourceAttributionRequest


class LifecycleTransitionRequest(BaseModel):
    evidence: SourceAttributionRequest


class SupersedeAttackPatternRequest(BaseModel):
    superseded_by: str
    evidence: SourceAttributionRequest


class SourceAttributionResponse(BaseModel):
    source_system: str
    reference: str
    observed_at: str
    notes: str = ""


class TacticMappingResponse(BaseModel):
    tactic_id: str
    tactic_shortname: str
    priority: int = 0
    notes: str = ""


class DetectionGuidanceResponse(BaseModel):
    content: str
    attribution: SourceAttributionResponse


class MitigationReferenceResponse(BaseModel):
    mitigation_id: str
    name: str
    description: str
    attribution: SourceAttributionResponse


class ProcedureExampleResponse(BaseModel):
    description: str
    attribution: SourceAttributionResponse
    actor_ref: str | None = None


class RelationshipMetadataResponse(BaseModel):
    relationship_type: str
    target_attack_pattern_id: str
    attribution: SourceAttributionResponse


class VersionRecordResponse(BaseModel):
    version: int
    changed_at: str
    change_summary: str
    source: str


class AttackPatternSummaryResponse(BaseModel):
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


class AttackPatternDetailResponse(BaseModel):
    attack_pattern_id: str
    tenant_id: str | None
    technique_id: str
    sub_technique_id: str | None
    lifecycle_status: str
    superseded_by: str | None
    created_at: str
    updated_at: str
    tactic_mappings: list[TacticMappingResponse] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    detection_guidance: list[DetectionGuidanceResponse] = Field(default_factory=list)
    mitigation_references: list[MitigationReferenceResponse] = Field(default_factory=list)
    procedure_examples: list[ProcedureExampleResponse] = Field(default_factory=list)
    relationship_metadata: list[RelationshipMetadataResponse] = Field(default_factory=list)
    version_history: list[VersionRecordResponse] = Field(default_factory=list)


class PaginatedAttackPatternListResponse(BaseModel):
    items: list[AttackPatternSummaryResponse]
    count: int
    limit: int
    offset: int
