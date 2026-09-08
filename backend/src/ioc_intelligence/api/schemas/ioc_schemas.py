"""Pydantic request/response schemas for ioc_intelligence's API
boundary (M51.2 Phase A4). Deliberately separate from the
application-layer DTOs in `ioc_intelligence.application.dtos`,
mirroring `threat_actor_intel.api.schemas.threat_actor_schemas`'s
convention: plain `BaseModel`s, shape/type/length validation only —
every actual invariant (provenance vocabulary, lifecycle/epistemic
policy, evidence existence, canonical dedup) is enforced by the
domain/application layers this schema is a thin transport wrapper
around.

Evidence citations are NOT accepted as a single opaque string here —
per the mission's explicit requirement, the request shape is
structured `(entity_type, entity_id)`, restricted to the entity types
`IIocEvidenceValidationPort`'s real adapter actually supports
(`SqlAlchemyEvidenceEntityExistenceService.SUPPORTED_ENTITY_TYPES`).
The canonical internal `"{entity_type}:{entity_id}"` citation string
is built in the route handler, never accepted directly from the
client."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

SupportedEvidenceEntityType = Literal["SecurityCondition", "InvestigationCase"]

# ── Requests ─────────────────────────────────────────────────────────────────


class SourceAttributionRequest(BaseModel):
    source_system: str = Field(min_length=1, max_length=64)
    external_id: str = Field(min_length=1, max_length=512)
    observed_at: str
    weight_applied: float = Field(gt=0.0, le=1.0)
    confidence: str
    content_hash: str | None = Field(default=None, max_length=256)


class EvidenceCitationRequest(BaseModel):
    entity_type: SupportedEvidenceEntityType
    entity_id: str = Field(min_length=1, max_length=512)

    def to_canonical_citation(self) -> str:
        return f"{self.entity_type}:{self.entity_id}"


class ObserveIocRequest(BaseModel):
    ioc_type: str
    raw_value: str = Field(min_length=1, max_length=2048)
    source_attributions: list[SourceAttributionRequest] = Field(default_factory=list)
    evidence_citations: list[EvidenceCitationRequest] = Field(default_factory=list)


class AddSourceAttributionRequest(BaseModel):
    attribution: SourceAttributionRequest


class AddEvidenceCitationRequest(BaseModel):
    citation: EvidenceCitationRequest


class TransitionLifecycleRequest(BaseModel):
    target_lifecycle: str


class TransitionEpistemicStateRequest(BaseModel):
    target_state: str


class RefuteIocRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2048)


# ── Responses ────────────────────────────────────────────────────────────────


class SourceAttributionResponse(BaseModel):
    source_system: str
    external_id: str
    content_hash: str | None
    observed_at: str
    weight_applied: float
    confidence: str


class EvidenceCitationResponse(BaseModel):
    value: str


class IocSummaryResponse(BaseModel):
    ioc_id: str
    tenant_id: str | None
    ioc_type: str
    canonical_key: str
    lifecycle: str
    epistemic_state: str
    created_at: str
    updated_at: str
    valid_until: str | None
    source_count: int
    evidence_count: int


class IocDetailResponse(BaseModel):
    ioc_id: str
    tenant_id: str | None
    ioc_type: str
    canonical_key: str
    lifecycle: str
    epistemic_state: str
    valid_from: str
    valid_until: str | None
    created_at: str
    updated_at: str
    source_attributions: list[SourceAttributionResponse] = Field(default_factory=list)
    evidence_citations: list[EvidenceCitationResponse] = Field(default_factory=list)


class PaginatedIocListResponse(BaseModel):
    items: list[IocSummaryResponse]
    # `count` = number of items on THIS page (== len(items)); `total` =
    # the real count of every row matching the applied filters across
    # the entire dataset, computed server-side before limit/offset —
    # never a client-side tally over one page. Both are kept (rather
    # than only `total`) so an existing caller reading `count` as
    # "this page's size" is not silently broken by this field's
    # long-standing meaning.
    count: int
    total: int
    limit: int
    offset: int


class ExpireLapsedIocsResponse(BaseModel):
    """Result of the bounded expiry-sweep maintenance operation — a real
    count of IOCs actually transitioned this call, never an estimate."""

    expired_count: int
