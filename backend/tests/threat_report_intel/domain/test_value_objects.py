from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from threat_report_intel.domain.exceptions.domain_exceptions import (
    EmptyIdentifierError,
    InvalidCanonicalTitleError,
)
from threat_report_intel.domain.value_objects.canonical_title import (
    normalize_canonical_title,
)
from threat_report_intel.domain.value_objects.enums import (
    ThreatReportConfidence,
    ThreatReportLifecycleStatus,
    ThreatReportSeverity,
    TlpMarking,
)
from threat_report_intel.domain.value_objects.evidence import (
    EvidenceCitation,
    SourceAttribution,
)
from threat_report_intel.domain.value_objects.identifiers import ThreatReportId
from threat_report_intel.domain.value_objects.publication import (
    Publisher,
    ReportMetadata,
    ThreatReportReference,
)
from threat_report_intel.domain.value_objects.version_record import VersionRecord

NOW = datetime(2026, 8, 6, tzinfo=UTC)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Operation Cloud Hopper", "operation cloud hopper"),
        ("  operation-cloud-hopper  ", "operation cloud hopper"),
        ("OPERATION_CLOUD__HOPPER", "operation cloud hopper"),
        ("Flash\tReport", "flash report"),
    ],
)
def test_canonical_title_normalization(raw: str, expected: str) -> None:
    assert normalize_canonical_title(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "-_-", "\t\n"])
def test_canonical_title_rejects_empty_forms(raw: str) -> None:
    with pytest.raises(InvalidCanonicalTitleError):
        normalize_canonical_title(raw)


def test_canonical_title_rejects_non_strings() -> None:
    with pytest.raises(InvalidCanonicalTitleError):
        normalize_canonical_title(None)  # type: ignore[arg-type]


def test_threat_report_id_rejects_nil_uuid() -> None:
    with pytest.raises(ValueError, match="nil UUID"):
        ThreatReportId(UUID(int=0))


def test_threat_report_id_generates_unique_values() -> None:
    assert ThreatReportId.generate() != ThreatReportId.generate()


def test_publisher_requires_an_organization_name() -> None:
    with pytest.raises(EmptyIdentifierError):
        Publisher(organization_name="  ")
    assert str(Publisher(organization_name="Acme")) == "Acme"
    assert Publisher(organization_name="Acme").contact == ""


def test_report_metadata_requires_a_free_text_report_type() -> None:
    with pytest.raises(EmptyIdentifierError):
        ReportMetadata(report_type=" ", tlp_marking=TlpMarking.TLP_GREEN)
    # Free text on purpose — publisher taxonomies are not RedForge's to close.
    metadata = ReportMetadata(report_type="quarterly-horizon-scan", tlp_marking=TlpMarking.TLP_RED)
    assert metadata.report_type == "quarterly-horizon-scan"
    assert metadata.external_report_id == ""


def test_reference_requires_a_url_or_citation() -> None:
    with pytest.raises(EmptyIdentifierError):
        ThreatReportReference(url_or_citation="")
    reference = ThreatReportReference(url_or_citation="https://example.test/a")
    assert str(reference) == "https://example.test/a"
    assert reference.description == ""


def test_evidence_citation_requires_a_value() -> None:
    with pytest.raises(EmptyIdentifierError):
        EvidenceCitation("   ")
    assert str(EvidenceCitation("note")) == "note"


def test_source_attribution_requires_source_and_reference() -> None:
    with pytest.raises(EmptyIdentifierError):
        SourceAttribution(source_system="", reference="r", observed_at=NOW)
    with pytest.raises(EmptyIdentifierError):
        SourceAttribution(source_system="s", reference=" ", observed_at=NOW)
    attribution = SourceAttribution(source_system="s", reference="r", observed_at=NOW)
    assert attribution.confidence is ThreatReportConfidence.MEDIUM


def test_version_record_validation() -> None:
    with pytest.raises(ValueError, match="version must be >= 1"):
        VersionRecord(version=0, changed_at=NOW, change_summary="x", source="s")
    with pytest.raises(EmptyIdentifierError):
        VersionRecord(version=1, changed_at=NOW, change_summary=" ", source="s")
    with pytest.raises(EmptyIdentifierError):
        VersionRecord(version=1, changed_at=NOW, change_summary="x", source="")


def test_closed_enums_carry_exactly_the_approved_vocabularies() -> None:
    assert {s.value for s in ThreatReportLifecycleStatus} == {
        "active",
        "deprecated",
        "revoked",
        "superseded",
    }
    assert {s.value for s in ThreatReportSeverity} == {
        "informational",
        "low",
        "medium",
        "high",
        "critical",
    }
    assert {c.value for c in ThreatReportConfidence} == {"low", "medium", "high", "very_high"}
    assert {t.value for t in TlpMarking} == {
        "tlp_red",
        "tlp_amber",
        "tlp_amber_strict",
        "tlp_green",
        "tlp_clear",
    }
