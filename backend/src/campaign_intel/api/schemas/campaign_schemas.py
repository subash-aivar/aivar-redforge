"""Pydantic request/response schemas for campaign_intel's API —
separate from the application-layer DTOs, mirroring
`malware_intel.api.schemas.malware_schemas`'s convention."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SourceAttributionRequest(BaseModel):
    source_system: str
    reference: str
    observed_at: str
    confidence: str = "medium"
    notes: str = ""


class ObjectiveRequest(BaseModel):
    objective_type: str
    description: str = ""


class TimelineRequest(BaseModel):
    first_observed: str
    last_observed: str | None = None
    ongoing: bool = False


class ObserveCampaignRequest(BaseModel):
    canonical_name: str
    status: str = "unknown"
    motivation: str = "unknown"
    confidence: str = "medium"
    timeline: TimelineRequest | None = None
    aliases: list[str] = Field(default_factory=list)
    objectives: list[ObjectiveRequest] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)
    target_sectors: list[str] = Field(default_factory=list)


class AddAliasRequest(BaseModel):
    alias: str


class AddObjectiveRequest(BaseModel):
    objective: ObjectiveRequest


class AddRegionRequest(BaseModel):
    region: str


class AddTargetSectorRequest(BaseModel):
    target_sector: str


class AddEvidenceCitationRequest(BaseModel):
    citation: str


class AddSourceAttributionRequest(BaseModel):
    attribution: SourceAttributionRequest


class TransitionStatusRequest(BaseModel):
    """Moves the REAL-WORLD campaign's operational status — not the
    RedForge record lifecycle."""

    target_status: str
    evidence: SourceAttributionRequest


class LifecycleTransitionRequest(BaseModel):
    """Moves the RedForge RECORD lifecycle — not the real-world
    campaign's status."""

    evidence: SourceAttributionRequest


class SupersedeCampaignRequest(BaseModel):
    superseded_by: str
    evidence: SourceAttributionRequest


class SourceAttributionResponse(BaseModel):
    source_system: str
    reference: str
    observed_at: str
    confidence: str = "medium"
    notes: str = ""


class ObjectiveResponse(BaseModel):
    objective_type: str
    description: str = ""


class TimelineResponse(BaseModel):
    first_observed: str
    last_observed: str | None = None
    ongoing: bool = False


class VersionRecordResponse(BaseModel):
    version: int
    changed_at: str
    change_summary: str
    source: str


class CampaignSummaryResponse(BaseModel):
    campaign_id: str
    tenant_id: str | None
    canonical_name: str
    status: str
    lifecycle_status: str
    motivation: str
    confidence: str
    created_at: str
    updated_at: str
    alias_count: int = 0
    objective_count: int = 0
    region_count: int = 0
    target_sector_count: int = 0


class CampaignDetailResponse(BaseModel):
    campaign_id: str
    tenant_id: str | None
    canonical_name: str
    status: str
    lifecycle_status: str
    motivation: str
    confidence: str
    superseded_by: str | None
    created_at: str
    updated_at: str
    timeline: TimelineResponse | None = None
    aliases: list[str] = Field(default_factory=list)
    objectives: list[ObjectiveResponse] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)
    target_sectors: list[str] = Field(default_factory=list)
    evidence_citations: list[str] = Field(default_factory=list)
    source_attributions: list[SourceAttributionResponse] = Field(default_factory=list)
    version_history: list[VersionRecordResponse] = Field(default_factory=list)


class PaginatedCampaignListResponse(BaseModel):
    items: list[CampaignSummaryResponse]
    count: int
    limit: int
    offset: int
