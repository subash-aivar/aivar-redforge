from __future__ import annotations

from datetime import UTC, date, datetime

import pytest

from threat_report_intel.domain.aggregates.threat_report import ThreatReport
from threat_report_intel.domain.specifications.threat_report_specifications import (
    ActiveThreatReportSpecification,
    DeprecatedOrRevokedThreatReportSpecification,
    HighSeverityThreatReportSpecification,
    IsGlobalThreatReportSpecification,
    IsTenantThreatReportSpecification,
    SupersededThreatReportSpecification,
)
from threat_report_intel.domain.value_objects.enums import (
    ThreatReportSeverity,
    TlpMarking,
)
from threat_report_intel.domain.value_objects.evidence import SourceAttribution
from threat_report_intel.domain.value_objects.identifiers import TenantId, ThreatReportId
from threat_report_intel.domain.value_objects.publication import Publisher, ReportMetadata

NOW = datetime(2026, 8, 6, tzinfo=UTC)
EVIDENCE = SourceAttribution(source_system="s", reference="r", observed_at=NOW)


def _report(
    *,
    tenant_id: TenantId | None = None,
    severity: ThreatReportSeverity = ThreatReportSeverity.MEDIUM,
    title: str = "Some Report",
) -> ThreatReport:
    return ThreatReport.observe(
        threat_report_id=ThreatReportId.generate(),
        tenant_id=tenant_id,
        title=title,
        publisher=Publisher(organization_name="Acme"),
        publication_date=date(2026, 7, 1),
        report_metadata=ReportMetadata(report_type="advisory", tlp_marking=TlpMarking.TLP_GREEN),
        executive_summary="Leadership-level.",
        technical_summary="Analyst-level.",
        now=NOW,
        severity=severity,
    )


def test_scope_specifications() -> None:
    tenant = TenantId.generate()
    assert IsTenantThreatReportSpecification().is_satisfied_by(_report(tenant_id=tenant))
    assert not IsGlobalThreatReportSpecification().is_satisfied_by(_report(tenant_id=tenant))
    assert IsGlobalThreatReportSpecification().is_satisfied_by(_report())
    assert not IsTenantThreatReportSpecification().is_satisfied_by(_report())


def test_active_specification() -> None:
    record = _report()
    assert ActiveThreatReportSpecification().is_satisfied_by(record)
    record.deprecate(None, EVIDENCE, NOW)
    assert not ActiveThreatReportSpecification().is_satisfied_by(record)


def test_deprecated_or_revoked_specification() -> None:
    spec = DeprecatedOrRevokedThreatReportSpecification()
    active = _report()
    assert not spec.is_satisfied_by(active)

    deprecated = _report()
    deprecated.deprecate(None, EVIDENCE, NOW)
    assert spec.is_satisfied_by(deprecated)

    revoked = _report()
    revoked.revoke(None, EVIDENCE, NOW)
    assert spec.is_satisfied_by(revoked)

    superseded = _report()
    superseded.supersede(None, ThreatReportId.generate(), EVIDENCE, NOW)
    assert not spec.is_satisfied_by(superseded)


def test_superseded_specification() -> None:
    record = _report()
    record.supersede(None, ThreatReportId.generate(), EVIDENCE, NOW)
    assert SupersededThreatReportSpecification().is_satisfied_by(record)


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (ThreatReportSeverity.INFORMATIONAL, False),
        (ThreatReportSeverity.LOW, False),
        (ThreatReportSeverity.MEDIUM, False),
        (ThreatReportSeverity.HIGH, True),
        (ThreatReportSeverity.CRITICAL, True),
    ],
)
def test_high_severity_specification(severity, expected) -> None:
    assert (
        HighSeverityThreatReportSpecification().is_satisfied_by(_report(severity=severity))
        is expected
    )
