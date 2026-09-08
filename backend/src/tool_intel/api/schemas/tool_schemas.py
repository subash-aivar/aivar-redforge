"""Pydantic request/response schemas for tool_intel's API — separate
from the application-layer DTOs, mirroring
`campaign_intel.api.schemas.campaign_schemas`'s convention."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SourceAttributionRequest(BaseModel):
    source_system: str
    reference: str
    observed_at: str
    confidence: str = "medium"
    notes: str = ""


class ObserveToolRequest(BaseModel):
    canonical_name: str
    category: str = "other"
    family: str | None = None
    confidence: str = "medium"
    aliases: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)


class AddAliasRequest(BaseModel):
    alias: str


class AddPlatformRequest(BaseModel):
    platform: str


class AddCapabilityRequest(BaseModel):
    capability: str


class AddEvidenceCitationRequest(BaseModel):
    citation: str


class AddSourceAttributionRequest(BaseModel):
    attribution: SourceAttributionRequest


class LifecycleTransitionRequest(BaseModel):
    """Moves the RedForge RECORD lifecycle — says nothing about whether
    the tool is still used in the wild."""

    evidence: SourceAttributionRequest


class SupersedeToolRequest(BaseModel):
    superseded_by: str
    evidence: SourceAttributionRequest


class SourceAttributionResponse(BaseModel):
    source_system: str
    reference: str
    observed_at: str
    confidence: str = "medium"
    notes: str = ""


class VersionRecordResponse(BaseModel):
    version: int
    changed_at: str
    change_summary: str
    source: str


class ToolSummaryResponse(BaseModel):
    tool_id: str
    tenant_id: str | None
    canonical_name: str
    category: str
    lifecycle_status: str
    family: str | None
    confidence: str
    created_at: str
    updated_at: str
    alias_count: int = 0
    platform_count: int = 0
    capability_count: int = 0


class ToolDetailResponse(BaseModel):
    tool_id: str
    tenant_id: str | None
    canonical_name: str
    category: str
    lifecycle_status: str
    family: str | None
    confidence: str
    superseded_by: str | None
    created_at: str
    updated_at: str
    aliases: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    evidence_citations: list[str] = Field(default_factory=list)
    source_attributions: list[SourceAttributionResponse] = Field(default_factory=list)
    version_history: list[VersionRecordResponse] = Field(default_factory=list)


class PaginatedToolListResponse(BaseModel):
    items: list[ToolSummaryResponse]
    count: int
    limit: int
    offset: int
