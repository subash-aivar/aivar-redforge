"""Real-PostgreSQL integration tests for `PgThreatReportRepository`."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

from tests.threat_report_intel.infrastructure.helpers import (
    make_attribution,
    make_tenant_id,
    make_threat_report,
    random_title,
)
from threat_report_intel.domain.value_objects.enums import (
    ThreatReportLifecycleStatus,
    ThreatReportSeverity,
    TlpMarking,
)
from threat_report_intel.domain.value_objects.evidence import EvidenceCitation
from threat_report_intel.domain.value_objects.identifiers import ThreatReportId
from threat_report_intel.domain.value_objects.publication import ThreatReportReference
from threat_report_intel.infrastructure.persistence.exceptions import (
    OptimisticLockConflictError,
    ThreatReportIntelIntegrityError,
)
from threat_report_intel.infrastructure.persistence.repositories.pg_threat_report_repository import (
    PgThreatReportRepository,
)

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"),
        reason="requires TEST_DATABASE_URL (real PostgreSQL)",
    ),
]

NOW = datetime(2026, 8, 6, tzinfo=UTC)


async def test_save_then_get_round_trips_the_aggregate(tr_session) -> None:
    repo = PgThreatReportRepository(tr_session)
    tenant_id = make_tenant_id()
    record = make_threat_report(tenant_id=tenant_id)
    await repo.save(record)
    await tr_session.commit()

    loaded = await repo.get(tenant_id, record.threat_report_id)
    assert loaded is not None
    assert loaded.threat_report_id == record.threat_report_id
    assert loaded.title == record.title
    assert loaded.canonical_title == record.canonical_title
    assert loaded.publisher.organization_name == "Acme Threat Labs"
    assert loaded.publisher.contact == "intel@acme.example"
    assert loaded.publication_date == record.publication_date
    assert loaded.report_metadata.report_type == "advisory"
    assert loaded.report_metadata.tlp_marking is TlpMarking.TLP_GREEN
    assert loaded.report_metadata.external_report_id == "ACME-2026-014"
    assert loaded.lifecycle_status is ThreatReportLifecycleStatus.ACTIVE


async def test_both_summaries_survive_a_round_trip_distinctly(tr_session) -> None:
    repo = PgThreatReportRepository(tr_session)
    record = make_threat_report(tenant_id=make_tenant_id())
    await repo.save(record)
    await tr_session.commit()

    loaded = await repo.get(record.tenant_id, record.threat_report_id)
    assert loaded is not None
    assert loaded.executive_summary == "Leadership-level impact summary."
    assert loaded.technical_summary == "Analyst-level mechanism and artefacts."
    assert loaded.executive_summary != loaded.technical_summary


async def test_child_collections_round_trip(tr_session) -> None:
    repo = PgThreatReportRepository(tr_session)
    tenant_id = make_tenant_id()
    record = make_threat_report(tenant_id=tenant_id)
    record.add_reference(
        tenant_id,
        ThreatReportReference(url_or_citation="https://example.test/a", description="mirror"),
        NOW,
    )
    record.add_evidence_citation(tenant_id, EvidenceCitation("peer note"), NOW)
    record.add_source_attribution(tenant_id, make_attribution(), NOW)
    await repo.save(record)
    await tr_session.commit()

    loaded = await repo.get(tenant_id, record.threat_report_id)
    assert loaded is not None
    assert [r.url_or_citation for r in loaded.references] == ["https://example.test/a"]
    assert loaded.references[0].description == "mirror"
    assert [c.value for c in loaded.evidence_citations] == ["peer note"]
    assert len(loaded.source_attributions) == 1
    assert [v.version for v in loaded.version_history] == [1, 2, 3, 4]


async def test_get_is_scope_enforced(tr_session) -> None:
    repo = PgThreatReportRepository(tr_session)
    tenant_id = make_tenant_id()
    record = make_threat_report(tenant_id=tenant_id)
    await repo.save(record)
    await tr_session.commit()

    assert await repo.get(make_tenant_id(), record.threat_report_id) is None
    assert await repo.get(None, record.threat_report_id) is None
    assert await repo.get_any(record.threat_report_id) is not None


async def test_get_any_returns_a_global_record(tr_session) -> None:
    repo = PgThreatReportRepository(tr_session)
    record = make_threat_report(tenant_id=None)
    await repo.save(record)
    await tr_session.commit()

    loaded = await repo.get(None, record.threat_report_id)
    assert loaded is not None
    assert loaded.tenant_id is None


async def test_get_by_identity_finds_the_canonical_title_within_scope(tr_session) -> None:
    repo = PgThreatReportRepository(tr_session)
    tenant_id = make_tenant_id()
    title = random_title()
    record = make_threat_report(tenant_id=tenant_id, title=title)
    await repo.save(record)
    await tr_session.commit()

    assert await repo.get_by_identity(tenant_id, title) is not None
    assert await repo.get_by_identity(None, title) is None
    assert await repo.get_by_identity(make_tenant_id(), title) is None


async def test_duplicate_identity_within_a_scope_is_rejected_by_the_database(tr_session) -> None:
    repo = PgThreatReportRepository(tr_session)
    tenant_id = make_tenant_id()
    title = random_title()
    await repo.save(make_threat_report(tenant_id=tenant_id, title=title))
    await tr_session.commit()

    with pytest.raises(ThreatReportIntelIntegrityError):
        await repo.save(make_threat_report(tenant_id=tenant_id, title=title))
        await tr_session.commit()
    await tr_session.rollback()


async def test_duplicate_global_identity_is_rejected_by_the_partial_index(tr_session) -> None:
    repo = PgThreatReportRepository(tr_session)
    title = random_title()
    await repo.save(make_threat_report(tenant_id=None, title=title))
    await tr_session.commit()

    with pytest.raises(ThreatReportIntelIntegrityError):
        await repo.save(make_threat_report(tenant_id=None, title=title))
        await tr_session.commit()
    await tr_session.rollback()


async def test_the_same_title_is_allowed_across_distinct_scopes(tr_session) -> None:
    repo = PgThreatReportRepository(tr_session)
    title = random_title()
    await repo.save(make_threat_report(tenant_id=None, title=title))
    await repo.save(make_threat_report(tenant_id=make_tenant_id(), title=title))
    await repo.save(make_threat_report(tenant_id=make_tenant_id(), title=title))
    await tr_session.commit()


async def test_row_version_increments_on_update(tr_session) -> None:
    repo = PgThreatReportRepository(tr_session)
    tenant_id = make_tenant_id()
    record = make_threat_report(tenant_id=tenant_id)
    await repo.save(record)
    await tr_session.commit()
    assert record.row_version == 1

    record.add_evidence_citation(tenant_id, EvidenceCitation("x"), NOW)
    await repo.save(record)
    await tr_session.commit()
    assert record.row_version == 2

    loaded = await repo.get(tenant_id, record.threat_report_id)
    assert loaded is not None
    assert loaded.row_version == 2


async def test_a_stale_row_version_raises_optimistic_lock_conflict(tr_session) -> None:
    repo = PgThreatReportRepository(tr_session)
    tenant_id = make_tenant_id()
    record = make_threat_report(tenant_id=tenant_id)
    await repo.save(record)
    await tr_session.commit()

    stale = await repo.get(tenant_id, record.threat_report_id)
    assert stale is not None

    record.add_evidence_citation(tenant_id, EvidenceCitation("first writer"), NOW)
    await repo.save(record)
    await tr_session.commit()

    stale.add_evidence_citation(tenant_id, EvidenceCitation("second writer"), NOW)
    with pytest.raises(OptimisticLockConflictError):
        await repo.save(stale)
    await tr_session.rollback()


async def test_lifecycle_transitions_persist(tr_session) -> None:
    repo = PgThreatReportRepository(tr_session)
    tenant_id = make_tenant_id()
    record = make_threat_report(tenant_id=tenant_id)
    await repo.save(record)
    await tr_session.commit()

    successor = ThreatReportId.generate()
    record.supersede(tenant_id, successor, make_attribution(), NOW)
    await repo.save(record)
    await tr_session.commit()

    loaded = await repo.get(tenant_id, record.threat_report_id)
    assert loaded is not None
    assert loaded.lifecycle_status is ThreatReportLifecycleStatus.SUPERSEDED
    assert loaded.superseded_by == successor


async def test_version_history_is_append_only_across_saves(tr_session) -> None:
    repo = PgThreatReportRepository(tr_session)
    tenant_id = make_tenant_id()
    record = make_threat_report(tenant_id=tenant_id)
    await repo.save(record)
    await tr_session.commit()

    record.add_evidence_citation(tenant_id, EvidenceCitation("a"), NOW)
    await repo.save(record)
    await tr_session.commit()
    record.add_evidence_citation(tenant_id, EvidenceCitation("b"), NOW)
    await repo.save(record)
    await tr_session.commit()

    loaded = await repo.get(tenant_id, record.threat_report_id)
    assert loaded is not None
    assert [v.version for v in loaded.version_history] == [1, 2, 3]


async def test_list_filters_and_paginates(tr_session) -> None:
    repo = PgThreatReportRepository(tr_session)
    tenant_id = make_tenant_id()
    await repo.save(
        make_threat_report(
            tenant_id=tenant_id,
            severity=ThreatReportSeverity.CRITICAL,
            tlp_marking=TlpMarking.TLP_RED,
        )
    )
    low = make_threat_report(
        tenant_id=tenant_id, severity=ThreatReportSeverity.LOW, tlp_marking=TlpMarking.TLP_CLEAR
    )
    low.deprecate(tenant_id, make_attribution(), NOW)
    await repo.save(low)
    await tr_session.commit()

    assert len(await repo.list(tenant_id)) == 2
    assert len(await repo.list(tenant_id, severity=ThreatReportSeverity.CRITICAL)) == 1
    assert len(await repo.list(tenant_id, tlp_marking=TlpMarking.TLP_RED)) == 1
    assert (
        len(await repo.list(tenant_id, lifecycle_status=ThreatReportLifecycleStatus.DEPRECATED))
        == 1
    )
    assert len(await repo.list(tenant_id, limit=1)) == 1
    assert len(await repo.list(tenant_id, limit=1, offset=1)) == 1
    assert len(await repo.list(tenant_id, limit=1, offset=5)) == 0


async def test_list_never_leaks_across_scopes(tr_session) -> None:
    repo = PgThreatReportRepository(tr_session)
    tenant_id = make_tenant_id()
    await repo.save(make_threat_report(tenant_id=tenant_id))
    await tr_session.commit()

    assert await repo.list(make_tenant_id()) == []
