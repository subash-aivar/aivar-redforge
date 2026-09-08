"""Pydantic request/response schemas for threat_report_intel's API —
separate from the application-layer DTOs, mirroring
`infrastructure_intel.api.schemas.infrastructure_schemas`'s
convention."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SourceAttributionRequest(BaseModel):
    source_system: str
    reference: str
    observed_at: str
    confidence: str = "medium"
    notes: str = ""


class PublisherRequest(BaseModel):
    organization_name: str
    contact: str = ""


class ReportMetadataRequest(BaseModel):
    report_type: str
    tlp_marking: str
    external_report_id: str = ""


class ThreatReportReferenceRequest(BaseModel):
    url_or_citation: str
    description: str = ""


class ObserveThreatReportRequest(BaseModel):
    title: str
    publisher: PublisherRequest
    publication_date: str
    report_metadata: ReportMetadataRequest
    executive_summary: str
    technical_summary: str
    severity: str = "medium"
    confidence: str = "medium"
    references: list[ThreatReportReferenceRequest] = Field(default_factory=list)


class AddReferenceRequest(BaseModel):
    reference: ThreatReportReferenceRequest


class AddEvidenceCitationRequest(BaseModel):
    citation: str


class AddSourceAttributionRequest(BaseModel):
    attribution: SourceAttributionRequest


class LifecycleTransitionRequest(BaseModel):
    """Moves the RedForge RECORD lifecycle — says nothing about whether
    the publisher has withdrawn or amended the report itself."""

    evidence: SourceAttributionRequest


class SupersedeThreatReportRequest(BaseModel):
    superseded_by: str
    evidence: SourceAttributionRequest


class SourceAttributionResponse(BaseModel):
    source_system: str
    reference: str
    observed_at: str
    confidence: str = "medium"
    notes: str = ""


class PublisherResponse(BaseModel):
    organization_name: str
    contact: str = ""


class ReportMetadataResponse(BaseModel):
    report_type: str
    tlp_marking: str
    external_report_id: str = ""


class ThreatReportReferenceResponse(BaseModel):
    url_or_citation: str
    description: str = ""


class VersionRecordResponse(BaseModel):
    version: int
    changed_at: str
    change_summary: str
    source: str


class ThreatReportSummaryResponse(BaseModel):
    threat_report_id: str
    tenant_id: str | None
    title: str
    canonical_title: str
    publisher: str
    publication_date: str
    report_type: str
    tlp_marking: str
    severity: str
    confidence: str
    lifecycle_status: str
    created_at: str
    updated_at: str
    reference_count: int = 0
    evidence_citation_count: int = 0
    source_attribution_count: int = 0


class ThreatReportDetailResponse(BaseModel):
    threat_report_id: str
    tenant_id: str | None
    title: str
    canonical_title: str
    publisher: PublisherResponse
    publication_date: str
    report_metadata: ReportMetadataResponse
    severity: str
    confidence: str
    executive_summary: str
    technical_summary: str
    lifecycle_status: str
    superseded_by: str | None
    created_at: str
    updated_at: str
    references: list[ThreatReportReferenceResponse] = Field(default_factory=list)
    evidence_citations: list[str] = Field(default_factory=list)
    source_attributions: list[SourceAttributionResponse] = Field(default_factory=list)
    version_history: list[VersionRecordResponse] = Field(default_factory=list)


class PaginatedThreatReportListResponse(BaseModel):
    items: list[ThreatReportSummaryResponse]
    count: int
    limit: int
    offset: int
