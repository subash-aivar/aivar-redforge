"""Pydantic request/response schemas for infrastructure_intel's API —
separate from the application-layer DTOs, mirroring
`tool_intel.api.schemas.tool_schemas`'s convention."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SourceAttributionRequest(BaseModel):
    source_system: str
    reference: str
    observed_at: str
    confidence: str = "medium"
    notes: str = ""


class NetworkOwnershipRequest(BaseModel):
    registrant_organization: str
    abuse_contact: str = ""
    notes: str = ""


class ObserveInfrastructureRequest(BaseModel):
    infrastructure_type: str
    normalized_identifier: str
    confidence: str = "medium"
    hosting_provider: str | None = None
    cloud_provider: str | None = None
    regions: list[str] = Field(default_factory=list)
    network_ownership: NetworkOwnershipRequest | None = None


class SetHostingProviderRequest(BaseModel):
    provider_name: str


class SetCloudProviderRequest(BaseModel):
    provider: str


class AddRegionRequest(BaseModel):
    region_code: str


class SetNetworkOwnershipRequest(BaseModel):
    ownership: NetworkOwnershipRequest


class AddEvidenceCitationRequest(BaseModel):
    citation: str


class AddSourceAttributionRequest(BaseModel):
    attribution: SourceAttributionRequest


class LifecycleTransitionRequest(BaseModel):
    """Moves the RedForge RECORD lifecycle — says nothing about whether
    the infrastructure is still reachable or still hosting anything."""

    evidence: SourceAttributionRequest


class SupersedeInfrastructureRequest(BaseModel):
    superseded_by: str
    evidence: SourceAttributionRequest


class SourceAttributionResponse(BaseModel):
    source_system: str
    reference: str
    observed_at: str
    confidence: str = "medium"
    notes: str = ""


class NetworkOwnershipResponse(BaseModel):
    registrant_organization: str
    abuse_contact: str = ""
    notes: str = ""


class VersionRecordResponse(BaseModel):
    version: int
    changed_at: str
    change_summary: str
    source: str


class InfrastructureSummaryResponse(BaseModel):
    infrastructure_id: str
    tenant_id: str | None
    infrastructure_type: str
    normalized_identifier: str
    lifecycle_status: str
    hosting_provider: str | None
    cloud_provider: str | None
    confidence: str
    created_at: str
    updated_at: str
    region_count: int = 0
    evidence_citation_count: int = 0
    source_attribution_count: int = 0


class InfrastructureDetailResponse(BaseModel):
    infrastructure_id: str
    tenant_id: str | None
    infrastructure_type: str
    normalized_identifier: str
    lifecycle_status: str
    hosting_provider: str | None
    cloud_provider: str | None
    network_ownership: NetworkOwnershipResponse | None
    confidence: str
    superseded_by: str | None
    created_at: str
    updated_at: str
    regions: list[str] = Field(default_factory=list)
    evidence_citations: list[str] = Field(default_factory=list)
    source_attributions: list[SourceAttributionResponse] = Field(default_factory=list)
    version_history: list[VersionRecordResponse] = Field(default_factory=list)


class PaginatedInfrastructureListResponse(BaseModel):
    items: list[InfrastructureSummaryResponse]
    count: int
    limit: int
    offset: int
