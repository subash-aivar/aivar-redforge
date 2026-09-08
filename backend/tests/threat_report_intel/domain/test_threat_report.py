from __future__ import annotations

from datetime import UTC, date, datetime

import pytest

from threat_report_intel.domain.aggregates.threat_report import ThreatReport
from threat_report_intel.domain.events.threat_report_events import (
    EvidenceCitationAdded,
    ReferenceAdded,
    SourceAttributionAdded,
    ThreatReportDeprecated,
    ThreatReportObserved,
    ThreatReportReactivated,
    ThreatReportRevoked,
    ThreatReportSuperseded,
)
from threat_report_intel.domain.exceptions.domain_exceptions import (
    EmptyIdentifierError,
    InvalidCanonicalTitleError,
    InvalidLifecycleTransitionError,
    TenantMismatchError,
)
from threat_report_intel.domain.factories.threat_report_factory import ThreatReportFactory
from threat_report_intel.domain.value_objects.enums import (
    ThreatReportConfidence,
    ThreatReportLifecycleStatus,
    ThreatReportSeverity,
)
from threat_report_intel.domain.value_objects.evidence import EvidenceCitation
from threat_report_intel.domain.value_objects.identifiers import TenantId, ThreatReportId
from threat_report_intel.domain.value_objects.publication import (
    Publisher,
    ReportMetadata,
    ThreatReportReference,
)

TITLE = "Operation Cloud Hopper: Technical Analysis"


def _observe(
    tenant_id: TenantId | None,
    now: datetime,
    publisher: Publisher,
    report_metadata: ReportMetadata,
    publication_date: date,
    *,
    title: str = TITLE,
    severity: ThreatReportSeverity = ThreatReportSeverity.HIGH,
) -> ThreatReport:
    return ThreatReport.observe(
        threat_report_id=ThreatReportId.generate(),
        tenant_id=tenant_id,
        title=title,
        publisher=publisher,
        publication_date=publication_date,
        report_metadata=report_metadata,
        executive_summary="Leadership-level impact summary.",
        technical_summary="Analyst-level mechanism and artefacts.",
        now=now,
        severity=severity,
        confidence=ThreatReportConfidence.HIGH,
    )


# ── Observation ──────────────────────────────────────────────────────────


def test_observe_sets_active_lifecycle_and_first_version(
    tenant_id, now, publisher, report_metadata, publication_date
) -> None:
    record = _observe(tenant_id, now, publisher, report_metadata, publication_date)
    assert record.lifecycle_status is ThreatReportLifecycleStatus.ACTIVE
    assert len(record.version_history) == 1
    assert record.version_history[0].version == 1
    assert record.version_history[0].change_summary == "Observed"
    assert record.row_version == 1


def test_observe_emits_threat_report_observed(
    tenant_id, now, publisher, report_metadata, publication_date
) -> None:
    record = _observe(tenant_id, now, publisher, report_metadata, publication_date)
    events = record.pop_events()
    assert len(events) == 1
    event = events[0]
    assert isinstance(event, ThreatReportObserved)
    assert event.canonical_title == "operation cloud hopper: technical analysis"
    assert event.publisher == "Acme Threat Labs"
    assert event.severity == "high"
    assert event.tlp_marking == "tlp_clear"
    assert event.tenant_id == str(tenant_id)
    assert record.pop_events() == []


def test_a_global_record_renders_an_empty_tenant_in_events(
    now, publisher, report_metadata, publication_date
) -> None:
    record = _observe(None, now, publisher, report_metadata, publication_date)
    assert record.pop_events()[0].tenant_id == ""


def test_title_is_kept_verbatim_while_canonical_title_is_normalized(
    tenant_id, now, publisher, report_metadata, publication_date
) -> None:
    record = _observe(
        tenant_id,
        now,
        publisher,
        report_metadata,
        publication_date,
        title="  Operation-Cloud_Hopper:   TECHNICAL Analysis ",
    )
    assert record.title == "Operation-Cloud_Hopper:   TECHNICAL Analysis"
    assert record.canonical_title == "operation cloud hopper: technical analysis"
    assert record.title != record.canonical_title


def test_titles_differing_only_in_separators_and_case_share_one_identity(
    tenant_id, now, publisher, report_metadata, publication_date
) -> None:
    a = _observe(tenant_id, now, publisher, report_metadata, publication_date, title=TITLE)
    b = _observe(
        tenant_id,
        now,
        publisher,
        report_metadata,
        publication_date,
        title="operation-cloud-hopper: technical_analysis",
    )
    assert a.canonical_title == b.canonical_title


def test_a_blank_title_is_rejected(
    tenant_id, now, publisher, report_metadata, publication_date
) -> None:
    with pytest.raises(InvalidCanonicalTitleError):
        _observe(tenant_id, now, publisher, report_metadata, publication_date, title="   -_- ")


def test_both_summaries_are_required_and_distinct(
    tenant_id, now, publisher, report_metadata, publication_date
) -> None:
    with pytest.raises(EmptyIdentifierError):
        ThreatReport.observe(
            threat_report_id=ThreatReportId.generate(),
            tenant_id=tenant_id,
            title=TITLE,
            publisher=publisher,
            publication_date=publication_date,
            report_metadata=report_metadata,
            executive_summary="   ",
            technical_summary="Analyst-level.",
            now=now,
        )
    with pytest.raises(EmptyIdentifierError):
        ThreatReport.observe(
            threat_report_id=ThreatReportId.generate(),
            tenant_id=tenant_id,
            title=TITLE,
            publisher=publisher,
            publication_date=publication_date,
            report_metadata=report_metadata,
            executive_summary="Leadership-level.",
            technical_summary="",
            now=now,
        )
    record = _observe(tenant_id, now, publisher, report_metadata, publication_date)
    assert record.executive_summary != record.technical_summary


def test_the_factory_is_the_supported_construction_path(
    tenant_id, now, publisher, report_metadata, publication_date
) -> None:
    record = ThreatReportFactory().observe(
        tenant_id=tenant_id,
        title="  Cloud Hopper Flash ",
        publisher=publisher,
        publication_date=publication_date,
        report_metadata=report_metadata,
        executive_summary="Leadership-level.",
        technical_summary="Analyst-level.",
        now=now,
    )
    assert record.canonical_title == "cloud hopper flash"
    assert record.lifecycle_status is ThreatReportLifecycleStatus.ACTIVE


# ── Enrichment ───────────────────────────────────────────────────────────


def test_add_reference_appends_version_and_emits(
    tenant_id, now, publisher, report_metadata, publication_date
) -> None:
    record = _observe(tenant_id, now, publisher, report_metadata, publication_date)
    record.pop_events()
    record.add_reference(
        tenant_id,
        ThreatReportReference(url_or_citation="https://example.test/r", description="mirror"),
        now,
    )
    assert len(record.references) == 1
    assert len(record.version_history) == 2
    events = record.pop_events()
    assert isinstance(events[0], ReferenceAdded)
    assert events[0].url_or_citation == "https://example.test/r"


def test_add_evidence_citation_appends_version_and_emits(
    tenant_id, now, publisher, report_metadata, publication_date
) -> None:
    record = _observe(tenant_id, now, publisher, report_metadata, publication_date)
    record.pop_events()
    record.add_evidence_citation(tenant_id, EvidenceCitation("peer review note"), now)
    assert len(record.evidence_citations) == 1
    assert len(record.version_history) == 2
    assert isinstance(record.pop_events()[0], EvidenceCitationAdded)


def test_add_source_attribution_records_the_source_system(
    tenant_id, now, publisher, report_metadata, publication_date, evidence
) -> None:
    record = _observe(tenant_id, now, publisher, report_metadata, publication_date)
    record.pop_events()
    record.add_source_attribution(tenant_id, evidence, now)
    assert record.version_history[-1].source == "redforge-analyst"
    event = record.pop_events()[0]
    assert isinstance(event, SourceAttributionAdded)
    assert event.confidence == "high"


def test_a_foreign_tenant_cannot_mutate(
    tenant_id, now, publisher, report_metadata, publication_date
) -> None:
    record = _observe(tenant_id, now, publisher, report_metadata, publication_date)
    with pytest.raises(TenantMismatchError):
        record.add_evidence_citation(TenantId.generate(), EvidenceCitation("x"), now)


# ── Record lifecycle ─────────────────────────────────────────────────────


def test_deprecate_then_reactivate_round_trips(
    tenant_id, now, publisher, report_metadata, publication_date, evidence
) -> None:
    record = _observe(tenant_id, now, publisher, report_metadata, publication_date)
    record.pop_events()
    record.deprecate(tenant_id, evidence, now)
    assert record.lifecycle_status is ThreatReportLifecycleStatus.DEPRECATED
    assert isinstance(record.pop_events()[0], ThreatReportDeprecated)
    record.reactivate(tenant_id, evidence, now)
    assert record.lifecycle_status is ThreatReportLifecycleStatus.ACTIVE
    assert isinstance(record.pop_events()[0], ThreatReportReactivated)


def test_revoke_is_terminal(
    tenant_id, now, publisher, report_metadata, publication_date, evidence
) -> None:
    record = _observe(tenant_id, now, publisher, report_metadata, publication_date)
    record.revoke(tenant_id, evidence, now)
    assert isinstance(record.pop_events()[-1], ThreatReportRevoked)
    for transition in ("deprecate", "reactivate"):
        with pytest.raises(InvalidLifecycleTransitionError):
            getattr(record, transition)(tenant_id, evidence, now)


def test_supersede_records_the_successor_and_only_revoke_follows(
    tenant_id, now, publisher, report_metadata, publication_date, evidence
) -> None:
    record = _observe(tenant_id, now, publisher, report_metadata, publication_date)
    record.pop_events()
    successor = ThreatReportId.generate()
    record.supersede(tenant_id, successor, evidence, now)
    assert record.lifecycle_status is ThreatReportLifecycleStatus.SUPERSEDED
    assert record.superseded_by == successor
    event = record.pop_events()[0]
    assert isinstance(event, ThreatReportSuperseded)
    assert event.superseded_by == str(successor)
    with pytest.raises(InvalidLifecycleTransitionError):
        record.reactivate(tenant_id, evidence, now)
    record.revoke(tenant_id, evidence, now)
    assert record.lifecycle_status is ThreatReportLifecycleStatus.REVOKED


def test_reactivate_clears_superseded_by(
    tenant_id, now, publisher, report_metadata, publication_date, evidence
) -> None:
    record = _observe(tenant_id, now, publisher, report_metadata, publication_date)
    record.deprecate(tenant_id, evidence, now)
    record.reactivate(tenant_id, evidence, now)
    assert record.superseded_by is None


def test_lifecycle_transitions_are_tenant_checked(
    tenant_id, now, publisher, report_metadata, publication_date, evidence
) -> None:
    record = _observe(tenant_id, now, publisher, report_metadata, publication_date)
    with pytest.raises(TenantMismatchError):
        record.deprecate(TenantId.generate(), evidence, now)


def test_version_history_is_append_only_and_monotonic(
    tenant_id, now, publisher, report_metadata, publication_date, evidence
) -> None:
    record = _observe(tenant_id, now, publisher, report_metadata, publication_date)
    later = datetime(2026, 8, 7, tzinfo=UTC)
    record.add_evidence_citation(tenant_id, EvidenceCitation("a"), later)
    record.add_source_attribution(tenant_id, evidence, later)
    record.deprecate(tenant_id, evidence, later)
    versions = [v.version for v in record.version_history]
    assert versions == [1, 2, 3, 4]
    assert record.updated_at == later
