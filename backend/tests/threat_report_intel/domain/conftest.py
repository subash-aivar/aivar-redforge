from __future__ import annotations

from datetime import UTC, date, datetime

import pytest

from threat_report_intel.domain.value_objects.enums import ThreatReportConfidence, TlpMarking
from threat_report_intel.domain.value_objects.evidence import SourceAttribution
from threat_report_intel.domain.value_objects.identifiers import TenantId
from threat_report_intel.domain.value_objects.publication import Publisher, ReportMetadata

NOW = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
PUBLICATION_DATE = date(2026, 7, 1)


@pytest.fixture
def now() -> datetime:
    return NOW


@pytest.fixture
def publication_date() -> date:
    return PUBLICATION_DATE


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId.generate()


@pytest.fixture
def publisher() -> Publisher:
    return Publisher(organization_name="Acme Threat Labs", contact="intel@acme.example")


@pytest.fixture
def report_metadata() -> ReportMetadata:
    return ReportMetadata(
        report_type="advisory",
        tlp_marking=TlpMarking.TLP_CLEAR,
        external_report_id="ACME-2026-014",
    )


@pytest.fixture
def evidence() -> SourceAttribution:
    return SourceAttribution(
        source_system="redforge-analyst",
        reference="report-42",
        observed_at=NOW,
        confidence=ThreatReportConfidence.HIGH,
    )
