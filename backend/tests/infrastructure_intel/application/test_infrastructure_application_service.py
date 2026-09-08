from __future__ import annotations

import pytest

from infrastructure_intel.application.commands.infrastructure_commands import (
    AddEvidenceCitationCommand,
    AddRegionCommand,
    AddSourceAttributionCommand,
    DeprecateInfrastructureCommand,
    NetworkOwnershipInput,
    ObserveInfrastructureCommand,
    ReactivateInfrastructureCommand,
    RevokeInfrastructureCommand,
    SetCloudProviderCommand,
    SetHostingProviderCommand,
    SetNetworkOwnershipCommand,
    SourceAttributionInput,
    SupersedeInfrastructureCommand,
)
from infrastructure_intel.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from infrastructure_intel.application.queries.infrastructure_queries import (
    MAX_LIST_LIMIT,
    GetInfrastructureQuery,
    ListInfrastructureQuery,
)
from infrastructure_intel.application.services.infrastructure_application_service import (
    InfrastructureApplicationService,
)
from infrastructure_intel.domain.exceptions.domain_exceptions import (
    DuplicateInfrastructureError,
    InvalidLifecycleTransitionError,
    InvalidNormalizedIdentifierError,
)
from infrastructure_intel.domain.value_objects.identifiers import (
    InfrastructureId,
    TenantId,
)
from tests.infrastructure_intel.application.fakes import (
    FakeUnitOfWork,
    InMemoryInfrastructureRepository,
    RecordingEventPublisher,
)

pytestmark = pytest.mark.asyncio


EVIDENCE = SourceAttributionInput(
    source_system="redforge-analyst",
    reference="report-42",
    observed_at="2026-08-06T12:00:00+00:00",
    confidence="high",
)


@pytest.fixture
def repo() -> InMemoryInfrastructureRepository:
    return InMemoryInfrastructureRepository()


@pytest.fixture
def events() -> RecordingEventPublisher:
    return RecordingEventPublisher()


@pytest.fixture
def uow(repo: InMemoryInfrastructureRepository) -> FakeUnitOfWork:
    return FakeUnitOfWork(repo)


@pytest.fixture
def service(
    uow: FakeUnitOfWork, events: RecordingEventPublisher
) -> InfrastructureApplicationService:
    return InfrastructureApplicationService(uow_factory=lambda: uow, event_publisher=events)


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId.generate()


async def _observe(
    service: InfrastructureApplicationService,
    tenant_id=None,
    infrastructure_type="asn",
    identifier="AS15169",
    **kw,
):
    return await service.observe(
        ObserveInfrastructureCommand(
            tenant_id=tenant_id,
            infrastructure_type=infrastructure_type,
            normalized_identifier=identifier,
            **kw,
        )
    )


# ── Observation ──────────────────────────────────────────────────────────


async def test_observe_returns_a_detail_dto_of_primitives(service, tenant_id) -> None:
    dto = await _observe(service, tenant_id, identifier="  as 15169 ")
    assert dto.normalized_identifier == "AS15169"
    assert dto.infrastructure_type == "asn"
    assert dto.tenant_id == str(tenant_id)
    assert dto.lifecycle_status == "active"
    assert dto.hosting_provider is None
    assert dto.cloud_provider is None
    assert dto.network_ownership is None
    assert isinstance(dto.infrastructure_id, str)
    assert len(dto.version_history) == 1


async def test_observe_accepts_the_full_shape(service) -> None:
    dto = await _observe(
        service,
        None,
        infrastructure_type="domain",
        identifier="EVIL.example.com",
        confidence="very_high",
        hosting_provider="Shady Hosting BV",
        cloud_provider="aws",
        regions=("us-east-1", "eu-west-1"),
        network_ownership=NetworkOwnershipInput(
            registrant_organization="Shady Hosting BV",
            abuse_contact="abuse@shady.example",
        ),
    )
    assert dto.normalized_identifier == "evil.example.com"
    assert dto.confidence == "very_high"
    assert dto.hosting_provider == "Shady Hosting BV"
    assert dto.cloud_provider == "aws"
    assert dto.regions == ("us-east-1", "eu-west-1")
    assert dto.network_ownership is not None
    assert dto.network_ownership.abuse_contact == "abuse@shady.example"


async def test_observe_commits_then_publishes(service, uow, events) -> None:
    await _observe(service)
    assert uow.committed is True
    assert len(events.all_published) == 1
    assert type(events.all_published[0]).__name__ == "InfrastructureObserved"


async def test_observe_rejects_a_duplicate_in_the_same_scope(service, tenant_id) -> None:
    await _observe(service, tenant_id, identifier="AS15169")
    with pytest.raises(DuplicateInfrastructureError):
        await _observe(service, tenant_id, identifier="  as15169  ")


async def test_the_same_identity_may_exist_in_two_different_scopes(service, tenant_id) -> None:
    other = TenantId.generate()
    await _observe(service, tenant_id)
    await _observe(service, other)
    await _observe(service, None)


async def test_the_same_identifier_under_two_types_is_not_a_duplicate(service) -> None:
    """A DOMAIN footprint and a HOSTING_PROVIDER that share a name are
    legitimately two records — the type is part of the identity."""
    await _observe(service, None, infrastructure_type="domain", identifier="evil.example.com")
    await _observe(
        service, None, infrastructure_type="hosting_provider", identifier="evil.example.com"
    )


async def test_observe_rejects_an_unnormalizable_identifier(service) -> None:
    with pytest.raises(InvalidNormalizedIdentifierError):
        await _observe(service, None, infrastructure_type="ip_address", identifier="not-an-ip")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("infrastructure_type", "not_a_type"),
        ("confidence", "nope"),
        ("cloud_provider", "oracle_cloud"),
    ],
)
async def test_observe_rejects_invalid_enum_values(service, field, value) -> None:
    kwargs = {"infrastructure_type": "asn", "identifier": "AS15169"}
    if field == "infrastructure_type":
        kwargs["infrastructure_type"] = value
    else:
        kwargs[field] = value
    with pytest.raises(ApplicationValidationError):
        await _observe(service, None, **kwargs)


async def test_an_empty_hosting_provider_string_means_no_provider(service) -> None:
    dto = await _observe(service, None, hosting_provider="  ")
    assert dto.hosting_provider is None


# ── Reads ────────────────────────────────────────────────────────────────


async def test_get_returns_the_record_in_its_own_scope(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    fetched = await service.get(
        GetInfrastructureQuery(tenant_id=tenant_id, infrastructure_id=created.infrastructure_id)
    )
    assert fetched.infrastructure_id == created.infrastructure_id


async def test_get_hides_a_record_from_another_tenant(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    with pytest.raises(ApplicationNotFoundError):
        await service.get(
            GetInfrastructureQuery(
                tenant_id=TenantId.generate(), infrastructure_id=created.infrastructure_id
            )
        )


async def test_get_hides_a_tenant_record_from_the_global_scope(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    with pytest.raises(ApplicationNotFoundError):
        await service.get(
            GetInfrastructureQuery(tenant_id=None, infrastructure_id=created.infrastructure_id)
        )


async def test_get_rejects_a_malformed_id(service) -> None:
    with pytest.raises(ApplicationValidationError):
        await service.get(GetInfrastructureQuery(tenant_id=None, infrastructure_id="not-a-uuid"))


async def test_get_raises_not_found_for_an_unknown_id(service) -> None:
    with pytest.raises(ApplicationNotFoundError):
        await service.get(
            GetInfrastructureQuery(
                tenant_id=None, infrastructure_id=str(InfrastructureId.generate())
            )
        )


async def test_get_scope_resolves_ownership(service, tenant_id) -> None:
    tenant_record = await _observe(service, tenant_id, identifier="AS15169")
    global_record = await _observe(service, None, identifier="AS64512")
    assert await service.get_scope(tenant_record.infrastructure_id) == tenant_id
    assert await service.get_scope(global_record.infrastructure_id) is None


async def test_get_scope_raises_not_found_for_an_unknown_id(service) -> None:
    with pytest.raises(ApplicationNotFoundError):
        await service.get_scope(str(InfrastructureId.generate()))


# ── Lists ────────────────────────────────────────────────────────────────


async def test_list_returns_only_the_requested_scope(service, tenant_id) -> None:
    await _observe(service, tenant_id, identifier="AS15169")
    await _observe(service, None, identifier="AS64512")
    tenant_items = await service.list(ListInfrastructureQuery(tenant_id=tenant_id))
    global_items = await service.list(ListInfrastructureQuery(tenant_id=None))
    assert [i.normalized_identifier for i in tenant_items] == ["AS15169"]
    assert [i.normalized_identifier for i in global_items] == ["AS64512"]


async def test_list_filters_by_lifecycle_status(service) -> None:
    await _observe(service, None, identifier="AS15169")
    doomed = await _observe(service, None, identifier="AS64512")
    await service.revoke(
        RevokeInfrastructureCommand(
            tenant_id=None, infrastructure_id=doomed.infrastructure_id, evidence=EVIDENCE
        )
    )
    active = await service.list(ListInfrastructureQuery(tenant_id=None, lifecycle_status="active"))
    revoked = await service.list(
        ListInfrastructureQuery(tenant_id=None, lifecycle_status="revoked")
    )
    assert [i.normalized_identifier for i in active] == ["AS15169"]
    assert [i.normalized_identifier for i in revoked] == ["AS64512"]


async def test_list_filters_by_infrastructure_type(service) -> None:
    await _observe(service, None, infrastructure_type="asn", identifier="AS15169")
    await _observe(service, None, infrastructure_type="domain", identifier="evil.example.com")
    items = await service.list(
        ListInfrastructureQuery(tenant_id=None, infrastructure_type="domain")
    )
    assert [i.normalized_identifier for i in items] == ["evil.example.com"]


async def test_list_filters_by_cloud_provider(service) -> None:
    await _observe(service, None, identifier="AS15169", cloud_provider="aws")
    await _observe(service, None, identifier="AS64512", cloud_provider="gcp")
    items = await service.list(ListInfrastructureQuery(tenant_id=None, cloud_provider="gcp"))
    assert [i.normalized_identifier for i in items] == ["AS64512"]


@pytest.mark.parametrize("field", ["lifecycle_status", "infrastructure_type", "cloud_provider"])
async def test_list_rejects_an_invalid_filter_value(service, field) -> None:
    with pytest.raises(ApplicationValidationError):
        await service.list(ListInfrastructureQuery(tenant_id=None, **{field: "nonsense"}))


async def test_summary_dto_reports_collection_counts(service) -> None:
    created = await _observe(service, None, regions=("us-east-1", "eu-west-1"))
    await service.add_evidence_citation(
        AddEvidenceCitationCommand(
            tenant_id=None, infrastructure_id=created.infrastructure_id, citation="https://v/r"
        )
    )
    await service.add_source_attribution(
        AddSourceAttributionCommand(
            tenant_id=None, infrastructure_id=created.infrastructure_id, attribution=EVIDENCE
        )
    )
    item = (await service.list(ListInfrastructureQuery(tenant_id=None)))[0]
    assert item.region_count == 2
    assert item.evidence_citation_count == 1
    assert item.source_attribution_count == 1


@pytest.mark.parametrize("limit", [0, -1, MAX_LIST_LIMIT + 1])
async def test_list_query_rejects_an_out_of_range_limit(limit: int) -> None:
    with pytest.raises(ApplicationValidationError):
        ListInfrastructureQuery(tenant_id=None, limit=limit)


async def test_list_query_rejects_a_negative_offset() -> None:
    with pytest.raises(ApplicationValidationError):
        ListInfrastructureQuery(tenant_id=None, offset=-1)


async def test_list_paginates(service) -> None:
    for i in range(5):
        await _observe(service, None, identifier=f"AS{1000 + i}")
    page = await service.list(ListInfrastructureQuery(tenant_id=None, limit=2, offset=0))
    assert len(page) == 2


# ── Enrichment ───────────────────────────────────────────────────────────


async def test_set_hosting_provider(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    dto = await service.set_hosting_provider(
        SetHostingProviderCommand(
            tenant_id=tenant_id,
            infrastructure_id=created.infrastructure_id,
            provider_name="OVH",
        )
    )
    assert dto.hosting_provider == "OVH"
    assert len(dto.version_history) == 2


async def test_set_cloud_provider(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    dto = await service.set_cloud_provider(
        SetCloudProviderCommand(
            tenant_id=tenant_id, infrastructure_id=created.infrastructure_id, provider="azure"
        )
    )
    assert dto.cloud_provider == "azure"


async def test_set_cloud_provider_rejects_an_unknown_provider(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    with pytest.raises(ApplicationValidationError):
        await service.set_cloud_provider(
            SetCloudProviderCommand(
                tenant_id=tenant_id,
                infrastructure_id=created.infrastructure_id,
                provider="oracle_cloud",
            )
        )


async def test_add_region(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    dto = await service.add_region(
        AddRegionCommand(
            tenant_id=tenant_id,
            infrastructure_id=created.infrastructure_id,
            region_code="ap-southeast-2",
        )
    )
    assert dto.regions == ("ap-southeast-2",)


async def test_set_network_ownership(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    dto = await service.set_network_ownership(
        SetNetworkOwnershipCommand(
            tenant_id=tenant_id,
            infrastructure_id=created.infrastructure_id,
            ownership=NetworkOwnershipInput(
                registrant_organization="Shady Hosting BV",
                abuse_contact="abuse@shady.example",
                notes="RIR record",
            ),
        )
    )
    assert dto.network_ownership is not None
    assert dto.network_ownership.registrant_organization == "Shady Hosting BV"
    assert dto.network_ownership.notes == "RIR record"


async def test_add_evidence_citation(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    dto = await service.add_evidence_citation(
        AddEvidenceCitationCommand(
            tenant_id=tenant_id,
            infrastructure_id=created.infrastructure_id,
            citation="https://vendor/report",
        )
    )
    assert dto.evidence_citations == ("https://vendor/report",)


async def test_add_source_attribution(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    dto = await service.add_source_attribution(
        AddSourceAttributionCommand(
            tenant_id=tenant_id,
            infrastructure_id=created.infrastructure_id,
            attribution=EVIDENCE,
        )
    )
    assert len(dto.source_attributions) == 1
    assert dto.source_attributions[0].source_system == "redforge-analyst"
    assert dto.source_attributions[0].confidence == "high"


async def test_add_source_attribution_rejects_a_malformed_timestamp(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    bad = SourceAttributionInput(source_system="s", reference="r", observed_at="not-a-timestamp")
    with pytest.raises(ApplicationValidationError):
        await service.add_source_attribution(
            AddSourceAttributionCommand(
                tenant_id=tenant_id,
                infrastructure_id=created.infrastructure_id,
                attribution=bad,
            )
        )


async def test_enrichment_on_a_foreign_tenant_is_not_found(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    with pytest.raises(ApplicationNotFoundError):
        await service.add_region(
            AddRegionCommand(
                tenant_id=TenantId.generate(),
                infrastructure_id=created.infrastructure_id,
                region_code="us-east-1",
            )
        )


# ── Record lifecycle ─────────────────────────────────────────────────────


async def test_deprecate_then_reactivate(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    deprecated = await service.deprecate(
        DeprecateInfrastructureCommand(
            tenant_id=tenant_id, infrastructure_id=created.infrastructure_id, evidence=EVIDENCE
        )
    )
    assert deprecated.lifecycle_status == "deprecated"
    reactivated = await service.reactivate(
        ReactivateInfrastructureCommand(
            tenant_id=tenant_id, infrastructure_id=created.infrastructure_id, evidence=EVIDENCE
        )
    )
    assert reactivated.lifecycle_status == "active"


async def test_revoke_is_terminal(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    await service.revoke(
        RevokeInfrastructureCommand(
            tenant_id=tenant_id, infrastructure_id=created.infrastructure_id, evidence=EVIDENCE
        )
    )
    with pytest.raises(InvalidLifecycleTransitionError):
        await service.reactivate(
            ReactivateInfrastructureCommand(
                tenant_id=tenant_id,
                infrastructure_id=created.infrastructure_id,
                evidence=EVIDENCE,
            )
        )


async def test_supersede_records_the_successor(service, tenant_id) -> None:
    created = await _observe(service, tenant_id, identifier="AS15169")
    successor = await _observe(service, tenant_id, identifier="AS64512")
    dto = await service.supersede(
        SupersedeInfrastructureCommand(
            tenant_id=tenant_id,
            infrastructure_id=created.infrastructure_id,
            superseded_by=successor.infrastructure_id,
            evidence=EVIDENCE,
        )
    )
    assert dto.lifecycle_status == "superseded"
    assert dto.superseded_by == successor.infrastructure_id


async def test_supersede_rejects_a_malformed_successor_id(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    with pytest.raises(ApplicationValidationError):
        await service.supersede(
            SupersedeInfrastructureCommand(
                tenant_id=tenant_id,
                infrastructure_id=created.infrastructure_id,
                superseded_by="not-a-uuid",
                evidence=EVIDENCE,
            )
        )


async def test_lifecycle_change_on_an_unknown_record_is_not_found(service) -> None:
    with pytest.raises(ApplicationNotFoundError):
        await service.deprecate(
            DeprecateInfrastructureCommand(
                tenant_id=None,
                infrastructure_id=str(InfrastructureId.generate()),
                evidence=EVIDENCE,
            )
        )


# ── Ordering guarantees ──────────────────────────────────────────────────


async def test_events_are_never_published_when_the_commit_fails(repo, events) -> None:
    failing_uow = FakeUnitOfWork(repo, fail_commit=True)
    service = InfrastructureApplicationService(
        uow_factory=lambda: failing_uow, event_publisher=events
    )
    with pytest.raises(RuntimeError, match="simulated commit failure"):
        await _observe(service)
    assert events.all_published == []
    assert failing_uow.rolled_back is True


async def test_each_mutation_publishes_its_own_batch(service, tenant_id, events) -> None:
    created = await _observe(service, tenant_id)
    await service.add_region(
        AddRegionCommand(
            tenant_id=tenant_id,
            infrastructure_id=created.infrastructure_id,
            region_code="us-east-1",
        )
    )
    await service.deprecate(
        DeprecateInfrastructureCommand(
            tenant_id=tenant_id, infrastructure_id=created.infrastructure_id, evidence=EVIDENCE
        )
    )
    assert len(events.published_batches) == 3
    assert [type(b[0]).__name__ for b in events.published_batches] == [
        "InfrastructureObserved",
        "RegionAdded",
        "InfrastructureDeprecated",
    ]


async def test_a_rejected_mutation_publishes_nothing(service, tenant_id, events) -> None:
    created = await _observe(service, tenant_id)
    await service.revoke(
        RevokeInfrastructureCommand(
            tenant_id=tenant_id, infrastructure_id=created.infrastructure_id, evidence=EVIDENCE
        )
    )
    batches_before = len(events.published_batches)
    with pytest.raises(InvalidLifecycleTransitionError):
        await service.deprecate(
            DeprecateInfrastructureCommand(
                tenant_id=tenant_id,
                infrastructure_id=created.infrastructure_id,
                evidence=EVIDENCE,
            )
        )
    assert len(events.published_batches) == batches_before
