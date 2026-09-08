from __future__ import annotations

import pytest

from tests.threat_report_intel.application.fakes import (
    FakeUnitOfWork,
    InMemoryThreatReportRepository,
    RecordingEventPublisher,
)
from threat_report_intel.application.commands.threat_report_commands import (
    AddEvidenceCitationCommand,
    AddReferenceCommand,
    AddSourceAttributionCommand,
    DeprecateThreatReportCommand,
    ObserveThreatReportCommand,
    PublisherInput,
    ReactivateThreatReportCommand,
    ReportMetadataInput,
    RevokeThreatReportCommand,
    SourceAttributionInput,
    SupersedeThreatReportCommand,
    ThreatReportReferenceInput,
)
from threat_report_intel.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from threat_report_intel.application.queries.threat_report_queries import (
    GetThreatReportQuery,
    ListThreatReportsQuery,
)
from threat_report_intel.application.services.threat_report_application_service import (
    ThreatReportApplicationService,
)
from threat_report_intel.domain.exceptions.domain_exceptions import (
    DuplicateThreatReportError,
    InvalidLifecycleTransitionError,
)
from threat_report_intel.domain.value_objects.identifiers import TenantId

pytestmark = pytest.mark.asyncio

EVIDENCE = SourceAttributionInput(
    source_system="redforge-analyst",
    reference="report-42",
    observed_at="2026-08-06T12:00:00+00:00",
    confidence="high",
)


@pytest.fixture
def repo() -> InMemoryThreatReportRepository:
    return InMemoryThreatReportRepository()


@pytest.fixture
def events() -> RecordingEventPublisher:
    return RecordingEventPublisher()


@pytest.fixture
def service(repo, events) -> ThreatReportApplicationService:
    return ThreatReportApplicationService(
        uow_factory=lambda: FakeUnitOfWork(repo), event_publisher=events
    )


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId.generate()


def _observe_cmd(tenant_id: TenantId | None, title: str = "Cloud Hopper Analysis", **kw):
    return ObserveThreatReportCommand(
        tenant_id=tenant_id,
        title=title,
        publisher=PublisherInput(organization_name="Acme Threat Labs"),
        publication_date="2026-07-01",
        report_metadata=ReportMetadataInput(report_type="advisory", tlp_marking="tlp_clear"),
        executive_summary="Leadership-level.",
        technical_summary="Analyst-level.",
        **kw,
    )


# ── Observation ──────────────────────────────────────────────────────────


async def test_observe_returns_a_detail_dto_and_publishes(service, events, tenant_id) -> None:
    dto = await service.observe(_observe_cmd(tenant_id))
    assert dto.canonical_title == "cloud hopper analysis"
    assert dto.title == "Cloud Hopper Analysis"
    assert dto.lifecycle_status == "active"
    assert dto.tenant_id == str(tenant_id)
    assert dto.executive_summary == "Leadership-level."
    assert dto.technical_summary == "Analyst-level."
    assert len(events.all_published) == 1


async def test_observe_rejects_a_duplicate_canonical_title_in_the_same_scope(
    service, tenant_id
) -> None:
    await service.observe(_observe_cmd(tenant_id))
    with pytest.raises(DuplicateThreatReportError):
        await service.observe(_observe_cmd(tenant_id, title="  cloud-hopper_ANALYSIS "))


async def test_the_same_title_is_allowed_across_distinct_scopes(service, tenant_id) -> None:
    await service.observe(_observe_cmd(tenant_id))
    await service.observe(_observe_cmd(TenantId.generate()))
    await service.observe(_observe_cmd(None))


async def test_observe_validates_enums_and_dates(service, tenant_id) -> None:
    with pytest.raises(ApplicationValidationError):
        await service.observe(_observe_cmd(tenant_id, severity="apocalyptic"))
    with pytest.raises(ApplicationValidationError):
        await service.observe(_observe_cmd(tenant_id, confidence="certain"))
    bad_date = ObserveThreatReportCommand(
        tenant_id=tenant_id,
        title="X",
        publisher=PublisherInput(organization_name="Acme"),
        publication_date="not-a-date",
        report_metadata=ReportMetadataInput(report_type="advisory", tlp_marking="tlp_clear"),
        executive_summary="e",
        technical_summary="t",
    )
    with pytest.raises(ApplicationValidationError):
        await service.observe(bad_date)
    bad_tlp = ObserveThreatReportCommand(
        tenant_id=tenant_id,
        title="Y",
        publisher=PublisherInput(organization_name="Acme"),
        publication_date="2026-07-01",
        report_metadata=ReportMetadataInput(report_type="advisory", tlp_marking="tlp_purple"),
        executive_summary="e",
        technical_summary="t",
    )
    with pytest.raises(ApplicationValidationError):
        await service.observe(bad_tlp)


async def test_observe_carries_initial_references(service, tenant_id) -> None:
    dto = await service.observe(
        _observe_cmd(
            tenant_id,
            references=(
                ThreatReportReferenceInput(
                    url_or_citation="https://example.test/a", description="original"
                ),
            ),
        )
    )
    assert len(dto.references) == 1
    assert dto.references[0].description == "original"


# ── Reads ────────────────────────────────────────────────────────────────


async def test_get_is_scope_enforced(service, tenant_id) -> None:
    dto = await service.observe(_observe_cmd(tenant_id))
    got = await service.get(
        GetThreatReportQuery(tenant_id=tenant_id, threat_report_id=dto.threat_report_id)
    )
    assert got.threat_report_id == dto.threat_report_id
    with pytest.raises(ApplicationNotFoundError):
        await service.get(
            GetThreatReportQuery(
                tenant_id=TenantId.generate(), threat_report_id=dto.threat_report_id
            )
        )


async def test_get_rejects_a_malformed_id(service, tenant_id) -> None:
    with pytest.raises(ApplicationValidationError):
        await service.get(GetThreatReportQuery(tenant_id=tenant_id, threat_report_id="nope"))


async def test_get_scope_resolves_ownership(service, tenant_id) -> None:
    tenant_dto = await service.observe(_observe_cmd(tenant_id))
    global_dto = await service.observe(_observe_cmd(None, title="Global Report"))
    assert await service.get_scope(tenant_dto.threat_report_id) == tenant_id
    assert await service.get_scope(global_dto.threat_report_id) is None
    with pytest.raises(ApplicationNotFoundError):
        await service.get_scope("00000000-0000-4000-8000-000000000001")


async def test_list_filters_by_lifecycle_severity_and_tlp(service, tenant_id) -> None:
    await service.observe(_observe_cmd(tenant_id, title="A", severity="critical"))
    b = await service.observe(_observe_cmd(tenant_id, title="B", severity="low"))
    await service.deprecate(
        DeprecateThreatReportCommand(
            tenant_id=tenant_id, threat_report_id=b.threat_report_id, evidence=EVIDENCE
        )
    )

    all_items = await service.list(ListThreatReportsQuery(tenant_id=tenant_id))
    assert len(all_items) == 2

    active = await service.list(
        ListThreatReportsQuery(tenant_id=tenant_id, lifecycle_status="active")
    )
    assert [i.title for i in active] == ["A"]

    critical = await service.list(ListThreatReportsQuery(tenant_id=tenant_id, severity="critical"))
    assert [i.title for i in critical] == ["A"]

    clear = await service.list(ListThreatReportsQuery(tenant_id=tenant_id, tlp_marking="tlp_clear"))
    assert len(clear) == 2

    amber = await service.list(ListThreatReportsQuery(tenant_id=tenant_id, tlp_marking="tlp_amber"))
    assert amber == []


async def test_list_rejects_bad_pagination_and_filters(service, tenant_id) -> None:
    with pytest.raises(ApplicationValidationError):
        ListThreatReportsQuery(tenant_id=tenant_id, limit=0)
    with pytest.raises(ApplicationValidationError):
        ListThreatReportsQuery(tenant_id=tenant_id, limit=1000)
    with pytest.raises(ApplicationValidationError):
        ListThreatReportsQuery(tenant_id=tenant_id, offset=-1)
    with pytest.raises(ApplicationValidationError):
        await service.list(ListThreatReportsQuery(tenant_id=tenant_id, lifecycle_status="zombie"))


async def test_list_is_scope_isolated(service, tenant_id) -> None:
    await service.observe(_observe_cmd(tenant_id))
    assert await service.list(ListThreatReportsQuery(tenant_id=TenantId.generate())) == []
    assert await service.list(ListThreatReportsQuery(tenant_id=None)) == []


# ── Enrichment ───────────────────────────────────────────────────────────


async def test_add_reference_citation_and_attribution(service, events, tenant_id) -> None:
    dto = await service.observe(_observe_cmd(tenant_id))
    rid = dto.threat_report_id

    dto = await service.add_reference(
        AddReferenceCommand(
            tenant_id=tenant_id,
            threat_report_id=rid,
            reference=ThreatReportReferenceInput(url_or_citation="https://example.test/x"),
        )
    )
    assert len(dto.references) == 1

    dto = await service.add_evidence_citation(
        AddEvidenceCitationCommand(tenant_id=tenant_id, threat_report_id=rid, citation="note")
    )
    assert dto.evidence_citations == ("note",)

    dto = await service.add_source_attribution(
        AddSourceAttributionCommand(tenant_id=tenant_id, threat_report_id=rid, attribution=EVIDENCE)
    )
    assert len(dto.source_attributions) == 1
    assert len(dto.version_history) == 4
    assert len(events.all_published) == 4


async def test_enrichment_on_a_foreign_scope_is_not_found(service, tenant_id) -> None:
    dto = await service.observe(_observe_cmd(tenant_id))
    with pytest.raises(ApplicationNotFoundError):
        await service.add_evidence_citation(
            AddEvidenceCitationCommand(
                tenant_id=TenantId.generate(),
                threat_report_id=dto.threat_report_id,
                citation="x",
            )
        )


# ── Record lifecycle ─────────────────────────────────────────────────────


async def test_full_lifecycle_flow(service, tenant_id) -> None:
    dto = await service.observe(_observe_cmd(tenant_id))
    rid = dto.threat_report_id

    dto = await service.deprecate(
        DeprecateThreatReportCommand(tenant_id=tenant_id, threat_report_id=rid, evidence=EVIDENCE)
    )
    assert dto.lifecycle_status == "deprecated"

    dto = await service.reactivate(
        ReactivateThreatReportCommand(tenant_id=tenant_id, threat_report_id=rid, evidence=EVIDENCE)
    )
    assert dto.lifecycle_status == "active"

    successor = await service.observe(_observe_cmd(tenant_id, title="Successor Report"))
    dto = await service.supersede(
        SupersedeThreatReportCommand(
            tenant_id=tenant_id,
            threat_report_id=rid,
            superseded_by=successor.threat_report_id,
            evidence=EVIDENCE,
        )
    )
    assert dto.lifecycle_status == "superseded"
    assert dto.superseded_by == successor.threat_report_id

    dto = await service.revoke(
        RevokeThreatReportCommand(tenant_id=tenant_id, threat_report_id=rid, evidence=EVIDENCE)
    )
    assert dto.lifecycle_status == "revoked"

    with pytest.raises(InvalidLifecycleTransitionError):
        await service.deprecate(
            DeprecateThreatReportCommand(
                tenant_id=tenant_id, threat_report_id=rid, evidence=EVIDENCE
            )
        )


async def test_supersede_rejects_a_malformed_successor_id(service, tenant_id) -> None:
    dto = await service.observe(_observe_cmd(tenant_id))
    with pytest.raises(ApplicationValidationError):
        await service.supersede(
            SupersedeThreatReportCommand(
                tenant_id=tenant_id,
                threat_report_id=dto.threat_report_id,
                superseded_by="not-a-uuid",
                evidence=EVIDENCE,
            )
        )


async def test_events_are_only_published_after_a_successful_commit(repo, events, tenant_id) -> None:
    failing = ThreatReportApplicationService(
        uow_factory=lambda: FakeUnitOfWork(repo, fail_commit=True), event_publisher=events
    )
    with pytest.raises(RuntimeError):
        await failing.observe(_observe_cmd(tenant_id))
    assert events.all_published == []
