"""Application DTOs for threat_report_intel. Frozen, primitive-typed
dataclasses only — no domain value objects or aggregate references ever
cross this boundary, mirroring `infrastructure_intel.application.dtos.
infrastructure_dtos`'s convention."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class SourceAttributionDTO:
    source_system: str
    reference: str
    observed_at: str
    confidence: str = "medium"
    notes: str = ""


@dataclass(frozen=True, slots=True)
class PublisherDTO:
    organization_name: str
    contact: str = ""


@dataclass(frozen=True, slots=True)
class ReportMetadataDTO:
    report_type: str
    tlp_marking: str
    external_report_id: str = ""


@dataclass(frozen=True, slots=True)
class ThreatReportReferenceDTO:
    url_or_citation: str
    description: str = ""


@dataclass(frozen=True, slots=True)
class VersionRecordDTO:
    version: int
    changed_at: str
    change_summary: str
    source: str


@dataclass(frozen=True, slots=True)
class ThreatReportSummaryDTO:
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


@dataclass(frozen=True, slots=True)
class ThreatReportDetailDTO:
    threat_report_id: str
    tenant_id: str | None
    title: str
    canonical_title: str
    publisher: PublisherDTO
    publication_date: str
    report_metadata: ReportMetadataDTO
    severity: str
    confidence: str
    # Two DISTINCT required summaries — leadership-level and
    # analyst-level. Never conflated, never merged into one field.
    executive_summary: str
    technical_summary: str
    lifecycle_status: str
    superseded_by: str | None
    created_at: str
    updated_at: str
    references: tuple[ThreatReportReferenceDTO, ...] = field(default_factory=tuple)
    evidence_citations: tuple[str, ...] = field(default_factory=tuple)
    source_attributions: tuple[SourceAttributionDTO, ...] = field(default_factory=tuple)
    version_history: tuple[VersionRecordDTO, ...] = field(default_factory=tuple)
