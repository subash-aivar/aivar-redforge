"""Pydantic request/response schemas for threat_actor_intel's API
boundary (M51.1 Phase 4). Deliberately separate from the application-
layer DTOs in `threat_actor_intel.application.dtos`, mirroring
`risk_engine.api.schemas.risk_schemas`'s convention of a plain
`BaseModel`, `model_validate(asdict(dto))`-friendly response shape.
No business rules here — only shape/type/length validation; every
actual invariant (duplicate alias, illegal transition, evidence
validity, association uniqueness) is enforced by the domain/
application layers this schema is a thin transport wrapper around."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Requests ─────────────────────────────────────────────────────────────────


class RegisterThreatActorRequest(BaseModel):
    name: str = Field(min_length=1, max_length=512)
    origin: str
    motivations: list[str] = Field(min_length=1)
    sophistication: str


class AddAliasRequest(BaseModel):
    alias: str = Field(min_length=1, max_length=512)


class AssociateTechniqueRequest(BaseModel):
    technique_id: str = Field(min_length=1, max_length=64)


class AssociateIndicatorRequest(BaseModel):
    indicator_id: str = Field(min_length=1, max_length=256)


class UpdateMotivationRequest(BaseModel):
    motivations: list[str] = Field(min_length=1)


class UpdateSophisticationRequest(BaseModel):
    sophistication: str


class TransitionStatusRequest(BaseModel):
    target_status: str


class CreateAssociationRequest(BaseModel):
    referenced_entity_type: str = Field(min_length=1, max_length=256)
    referenced_entity_id: str = Field(min_length=1, max_length=512)
    evidence_citation: str = Field(min_length=1, max_length=2048)


# ── Responses ────────────────────────────────────────────────────────────────


class ThreatActorSummaryResponse(BaseModel):
    threat_actor_id: str
    tenant_id: str | None
    name: str
    origin: str
    status: str
    attribution_confidence: str


class ThreatActorDetailResponse(BaseModel):
    threat_actor_id: str
    tenant_id: str | None
    name: str
    origin: str
    status: str
    attribution_confidence: str
    sophistication: str
    motivations: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    technique_refs: list[str] = Field(default_factory=list)
    indicator_refs: list[str] = Field(default_factory=list)
    created_at: str
    updated_at: str


class ListThreatActorsResponse(BaseModel):
    items: list[ThreatActorSummaryResponse]
    count: int


class ThreatActorAssociationResponse(BaseModel):
    association_id: str
    tenant_id: str
    threat_actor_id: str
    referenced_entity_type: str
    referenced_entity_id: str
    evidence_citation: str
    state: str
    created_at: str
    retracted_at: str | None = None


class ListThreatActorAssociationsResponse(BaseModel):
    items: list[ThreatActorAssociationResponse]
    count: int
