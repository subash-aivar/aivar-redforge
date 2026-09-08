from __future__ import annotations

import random
from datetime import UTC, date, datetime

from threat_report_intel.domain.aggregates.threat_report import ThreatReport
from threat_report_intel.domain.value_objects.enums import (
    ThreatReportConfidence,
    ThreatReportSeverity,
    TlpMarking,
)
from threat_report_intel.domain.value_objects.evidence import SourceAttribution
from threat_report_intel.domain.value_objects.identifiers import TenantId, ThreatReportId
from threat_report_intel.domain.value_objects.publication import Publisher, ReportMetadata


def make_tenant_id() -> TenantId:
    return TenantId.generate()


def random_title() -> str:
    """Already normalized (lowercase, single-spaced) so a raw-string
    repository lookup matches what the aggregate stores."""
    return f"operation report {random.randint(1, 10**12)}"


def make_attribution(source_system: str = "redforge-analyst") -> SourceAttribution:
    return SourceAttribution(
        source_system=source_system,
        reference=f"ref-{random.randint(1, 10**9)}",
        observed_at=datetime(2026, 8, 6, tzinfo=UTC),
        confidence=ThreatReportConfidence.HIGH,
    )


def make_threat_report(
    *,
    tenant_id: TenantId | None = None,
    title: str | None = None,
    severity: ThreatReportSeverity = ThreatReportSeverity.MEDIUM,
    confidence: ThreatReportConfidence = ThreatReportConfidence.MEDIUM,
    tlp_marking: TlpMarking = TlpMarking.TLP_GREEN,
    report_type: str = "advisory",
) -> ThreatReport:
    now = datetime(2026, 8, 6, tzinfo=UTC)
    return ThreatReport.observe(
        threat_report_id=ThreatReportId.generate(),
        tenant_id=tenant_id,
        title=title if title is not None else random_title(),
        publisher=Publisher(organization_name="Acme Threat Labs", contact="intel@acme.example"),
        publication_date=date(2026, 7, 1),
        report_metadata=ReportMetadata(
            report_type=report_type,
            tlp_marking=tlp_marking,
            external_report_id="ACME-2026-014",
        ),
        executive_summary="Leadership-level impact summary.",
        technical_summary="Analyst-level mechanism and artefacts.",
        now=now,
        severity=severity,
        confidence=confidence,
    )
