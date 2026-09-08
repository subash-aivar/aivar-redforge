"""Aggregate -> DTO mappers for threat_report_intel."""

from __future__ import annotations

from typing import TYPE_CHECKING

from threat_report_intel.application.dtos.threat_report_dtos import (
    PublisherDTO,
    ReportMetadataDTO,
    SourceAttributionDTO,
    ThreatReportDetailDTO,
    ThreatReportReferenceDTO,
    ThreatReportSummaryDTO,
    VersionRecordDTO,
)

if TYPE_CHECKING:
    from threat_report_intel.domain.aggregates.threat_report import ThreatReport
    from threat_report_intel.domain.value_objects.evidence import SourceAttribution


def _attribution_dto(attribution: SourceAttribution) -> SourceAttributionDTO:
    return SourceAttributionDTO(
        source_system=attribution.source_system,
        reference=attribution.reference,
        observed_at=attribution.observed_at.isoformat(),
        confidence=attribution.confidence.value,
        notes=attribution.notes,
    )


def to_summary_dto(record: ThreatReport) -> ThreatReportSummaryDTO:
    return ThreatReportSummaryDTO(
        threat_report_id=str(record.threat_report_id),
        tenant_id=str(record.tenant_id) if record.tenant_id is not None else None,
        title=record.title,
        canonical_title=record.canonical_title,
        publisher=record.publisher.organization_name,
        publication_date=record.publication_date.isoformat(),
        report_type=record.report_metadata.report_type,
        tlp_marking=record.report_metadata.tlp_marking.value,
        severity=record.severity.value,
        confidence=record.confidence.value,
        lifecycle_status=record.lifecycle_status.value,
        created_at=record.created_at.isoformat(),
        updated_at=record.updated_at.isoformat(),
        reference_count=len(record.references),
        evidence_citation_count=len(record.evidence_citations),
        source_attribution_count=len(record.source_attributions),
    )


def to_detail_dto(record: ThreatReport) -> ThreatReportDetailDTO:
    return ThreatReportDetailDTO(
        threat_report_id=str(record.threat_report_id),
        tenant_id=str(record.tenant_id) if record.tenant_id is not None else None,
        title=record.title,
        canonical_title=record.canonical_title,
        publisher=PublisherDTO(
            organization_name=record.publisher.organization_name,
            contact=record.publisher.contact,
        ),
        publication_date=record.publication_date.isoformat(),
        report_metadata=ReportMetadataDTO(
            report_type=record.report_metadata.report_type,
            tlp_marking=record.report_metadata.tlp_marking.value,
            external_report_id=record.report_metadata.external_report_id,
        ),
        severity=record.severity.value,
        confidence=record.confidence.value,
        executive_summary=record.executive_summary,
        technical_summary=record.technical_summary,
        lifecycle_status=record.lifecycle_status.value,
        superseded_by=(str(record.superseded_by) if record.superseded_by is not None else None),
        created_at=record.created_at.isoformat(),
        updated_at=record.updated_at.isoformat(),
        references=tuple(
            ThreatReportReferenceDTO(url_or_citation=r.url_or_citation, description=r.description)
            for r in record.references
        ),
        evidence_citations=tuple(e.value for e in record.evidence_citations),
        source_attributions=tuple(_attribution_dto(a) for a in record.source_attributions),
        version_history=tuple(
            VersionRecordDTO(
                version=v.version,
                changed_at=v.changed_at.isoformat(),
                change_summary=v.change_summary,
                source=v.source,
            )
            for v in record.version_history
        ),
    )
