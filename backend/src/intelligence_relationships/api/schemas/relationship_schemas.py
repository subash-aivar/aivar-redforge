"""Pydantic request/response schemas for intelligence_relationships'
API (M51.4 Phase C1) — separate from the application-layer DTOs,
mirroring `attack_pattern_intel.api.schemas.attack_pattern_schemas`'s
convention."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SourceAttributionRequest(BaseModel):
    source_system: str
    reference: str
    observed_at: str
    confidence: str = "medium"
    notes: str = ""


class EntityRefRequest(BaseModel):
    entity_type: str
    entity_id: str


class ObserveRelationshipRequest(BaseModel):
    relationship_type: str
    source_entity: EntityRefRequest
    target_entity: EntityRefRequest
    direction: str = "unidirectional"
    confidence: str = "medium"
    epistemic_state: str = "observation"
    valid_from: str | None = None
    valid_until: str | None = None
    evidence_citations: list[str] = Field(default_factory=list)
    source_attributions: list[SourceAttributionRequest] = Field(default_factory=list)


class AddEvidenceCitationRequest(BaseModel):
    value: str


class AddSourceAttributionRequest(BaseModel):
    attribution: SourceAttributionRequest


class TransitionEpistemicStateRequest(BaseModel):
    target_state: str
    evidence: SourceAttributionRequest


class LifecycleTransitionRequest(BaseModel):
    evidence: SourceAttributionRequest


class SupersedeRelationshipRequest(BaseModel):
    superseded_by: str
    evidence: SourceAttributionRequest


class SourceAttributionResponse(BaseModel):
    source_system: str
    reference: str
    observed_at: str
    confidence: str
    notes: str = ""


class EntityRefResponse(BaseModel):
    entity_type: str
    entity_id: str


class EvidenceCitationResponse(BaseModel):
    value: str


class VersionRecordResponse(BaseModel):
    version: int
    changed_at: str
    change_summary: str
    source: str


class RelationshipSummaryResponse(BaseModel):
    relationship_id: str
    tenant_id: str | None
    relationship_type: str
    source_entity: EntityRefResponse
    target_entity: EntityRefResponse
    direction: str
    confidence: str
    epistemic_state: str
    lifecycle_status: str
    created_at: str
    updated_at: str
    evidence_citation_count: int = 0
    source_attribution_count: int = 0


class RelationshipDetailResponse(BaseModel):
    relationship_id: str
    tenant_id: str | None
    relationship_type: str
    source_entity: EntityRefResponse
    target_entity: EntityRefResponse
    direction: str
    confidence: str
    epistemic_state: str
    lifecycle_status: str
    superseded_by: str | None
    valid_from: str
    valid_until: str | None
    created_at: str
    updated_at: str
    evidence_citations: list[EvidenceCitationResponse] = Field(default_factory=list)
    source_attributions: list[SourceAttributionResponse] = Field(default_factory=list)
    version_history: list[VersionRecordResponse] = Field(default_factory=list)


class PaginatedRelationshipListResponse(BaseModel):
    items: list[RelationshipSummaryResponse]
    count: int
    limit: int
    offset: int
