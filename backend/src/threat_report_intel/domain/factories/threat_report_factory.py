"""ThreatReportFactory — the single supported construction path for
`ThreatReport` aggregates.

Stays pure/sync: it performs no I/O and calls no port. The aggregate
derives `canonical_title` from the raw `title` itself, so callers may
hand this factory raw analyst input. Scope-level uniqueness of
`canonical_title` must already have been checked by the application
service (repository existence check) BEFORE this factory is invoked —
mirroring `infrastructure_intel`'s exact factory-stays-pure discipline.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from threat_report_intel.domain.aggregates.threat_report import ThreatReport
from threat_report_intel.domain.value_objects.enums import (
    ThreatReportConfidence,
    ThreatReportSeverity,
)
from threat_report_intel.domain.value_objects.identifiers import ThreatReportId

if TYPE_CHECKING:
    from datetime import date, datetime

    from threat_report_intel.domain.value_objects.identifiers import TenantId
    from threat_report_intel.domain.value_objects.publication import (
        Publisher,
        ReportMetadata,
        ThreatReportReference,
    )


class ThreatReportFactory:
    def observe(
        self,
        tenant_id: TenantId | None,
        title: str,
        publisher: Publisher,
        publication_date: date,
        report_metadata: ReportMetadata,
        executive_summary: str,
        technical_summary: str,
        now: datetime,
        severity: ThreatReportSeverity = ThreatReportSeverity.MEDIUM,
        confidence: ThreatReportConfidence = ThreatReportConfidence.MEDIUM,
        references: tuple[ThreatReportReference, ...] = (),
    ) -> ThreatReport:
        return ThreatReport.observe(
            threat_report_id=ThreatReportId.generate(),
            tenant_id=tenant_id,
            title=title,
            publisher=publisher,
            publication_date=publication_date,
            report_metadata=report_metadata,
            executive_summary=executive_summary,
            technical_summary=technical_summary,
            now=now,
            severity=severity,
            confidence=confidence,
            references=references,
        )
