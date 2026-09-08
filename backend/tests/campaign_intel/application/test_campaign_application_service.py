from __future__ import annotations

from uuid import uuid4

import pytest

from campaign_intel.application.commands.campaign_commands import (
    AddAliasCommand,
    AddEvidenceCitationCommand,
    AddObjectiveCommand,
    AddRegionCommand,
    AddSourceAttributionCommand,
    AddTargetSectorCommand,
    DeprecateCampaignCommand,
    ObjectiveInput,
    ObserveCampaignCommand,
    ReactivateCampaignCommand,
    RevokeCampaignCommand,
    SourceAttributionInput,
    SupersedeCampaignCommand,
    TimelineInput,
    TransitionCampaignStatusCommand,
)
from campaign_intel.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from campaign_intel.application.queries.campaign_queries import (
    MAX_LIST_LIMIT,
    GetCampaignQuery,
    ListCampaignsQuery,
)
from campaign_intel.application.services.campaign_application_service import (
    CampaignApplicationService,
)
from campaign_intel.domain.events.campaign_events import (
    AliasAdded,
    CampaignDeprecated,
    CampaignObserved,
    StatusTransitioned,
)
from campaign_intel.domain.exceptions.domain_exceptions import (
    DuplicateCampaignError,
    InvalidCanonicalNameError,
    InvalidLifecycleTransitionError,
    InvalidRegionError,
    InvalidStatusTransitionError,
)
from campaign_intel.domain.value_objects.identifiers import TenantId
from tests.campaign_intel.application.fakes import (
    FakeUnitOfWork,
    InMemoryCampaignRepository,
    RecordingEventPublisher,
)

pytestmark = pytest.mark.asyncio

ATTRIBUTION = SourceAttributionInput(
    source_system="redforge-analyst",
    reference="ref-1",
    observed_at="2026-08-05T00:00:00+00:00",
    confidence="high",
)


@pytest.fixture
def repo() -> InMemoryCampaignRepository:
    return InMemoryCampaignRepository()


@pytest.fixture
def events() -> RecordingEventPublisher:
    return RecordingEventPublisher()


@pytest.fixture
def uow(repo: InMemoryCampaignRepository) -> FakeUnitOfWork:
    return FakeUnitOfWork(repo)


@pytest.fixture
def svc(uow: FakeUnitOfWork, events: RecordingEventPublisher) -> CampaignApplicationService:
    return CampaignApplicationService(uow_factory=lambda: uow, event_publisher=events)


@pytest.fixture
def tenant() -> TenantId:
    return TenantId.generate()


async def _observe(
    svc: CampaignApplicationService,
    tenant_id: TenantId | None,
    name: str = "Cloud Hopper",
    **kw: object,
):
    return await svc.observe(
        ObserveCampaignCommand(tenant_id=tenant_id, canonical_name=name, **kw)  # type: ignore[arg-type]
    )


# ── Observe ─────────────────────────────────────────────────────────────


async def test_observe_returns_detail_dto_with_normalized_name(
    svc: CampaignApplicationService, tenant: TenantId
) -> None:
    dto = await _observe(svc, tenant, "  CLOUD-HOPPER ")
    assert dto.canonical_name == "cloud hopper"
    assert dto.tenant_id == str(tenant)
    assert dto.lifecycle_status == "active"
    assert dto.status == "unknown"
    assert len(dto.version_history) == 1


async def test_observe_global_has_null_tenant(svc: CampaignApplicationService) -> None:
    dto = await _observe(svc, None)
    assert dto.tenant_id is None


async def test_observe_commits_then_publishes(
    svc: CampaignApplicationService, uow: FakeUnitOfWork, events: RecordingEventPublisher
) -> None:
    await _observe(svc, None)
    assert uow.committed
    assert isinstance(events.all_published[0], CampaignObserved)


async def test_observe_rejects_duplicate_in_same_scope(
    svc: CampaignApplicationService, tenant: TenantId
) -> None:
    await _observe(svc, tenant, "Cloud Hopper")
    with pytest.raises(DuplicateCampaignError):
        await _observe(svc, tenant, "  cloud_hopper  ")


async def test_observe_dedup_is_scope_aware(
    svc: CampaignApplicationService, tenant: TenantId
) -> None:
    await _observe(svc, tenant, "Cloud Hopper")
    await _observe(svc, None, "Cloud Hopper")
    await _observe(svc, TenantId.generate(), "Cloud Hopper")


async def test_observe_rejects_unnormalizable_name(svc: CampaignApplicationService) -> None:
    with pytest.raises(InvalidCanonicalNameError):
        await _observe(svc, None, "   ")


async def test_observe_accepts_full_taxonomy(svc: CampaignApplicationService) -> None:
    dto = await _observe(
        svc,
        None,
        "Cloud Hopper",
        status="ongoing",
        motivation="espionage",
        confidence="very_high",
        timeline=TimelineInput(first_observed="2024-01-01T00:00:00+00:00", ongoing=True),
        aliases=("APT10",),
        objectives=(ObjectiveInput(objective_type="espionage", description="steal IP"),),
        regions=("eu", "us"),
        target_sectors=("technology", "government"),
    )
    assert dto.status == "ongoing"
    assert dto.motivation == "espionage"
    assert dto.confidence == "very_high"
    assert dto.aliases == ("APT10",)
    assert dto.objectives[0].objective_type == "espionage"
    assert dto.regions == ("EU", "US")
    assert dto.target_sectors == ("technology", "government")
    assert dto.timeline is not None
    assert dto.timeline.ongoing is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "paused"),
        ("motivation", "curiosity"),
        ("confidence", "certain"),
        ("target_sectors", ("aerospace",)),
        ("objectives", (ObjectiveInput(objective_type="world_domination"),)),
    ],
)
async def test_observe_rejects_values_outside_closed_vocabulary(
    svc: CampaignApplicationService, field: str, value: object
) -> None:
    with pytest.raises(ApplicationValidationError):
        await _observe(svc, None, "Cloud Hopper", **{field: value})


async def test_observe_rejects_bad_region_format(svc: CampaignApplicationService) -> None:
    with pytest.raises(InvalidRegionError):
        await _observe(svc, None, "Cloud Hopper", regions=("!!",))


async def test_observe_rejects_malformed_timeline(svc: CampaignApplicationService) -> None:
    with pytest.raises(ApplicationValidationError):
        await _observe(svc, None, "Cloud Hopper", timeline=TimelineInput(first_observed="nope"))


# ── Reads ───────────────────────────────────────────────────────────────


async def test_get_scope_returns_owner(svc: CampaignApplicationService, tenant: TenantId) -> None:
    dto = await _observe(svc, tenant)
    assert await svc.get_scope(dto.campaign_id) == tenant


async def test_get_scope_returns_none_for_global(svc: CampaignApplicationService) -> None:
    dto = await _observe(svc, None)
    assert await svc.get_scope(dto.campaign_id) is None


async def test_get_scope_raises_for_unknown(svc: CampaignApplicationService) -> None:
    with pytest.raises(ApplicationNotFoundError):
        await svc.get_scope(str(uuid4()))


async def test_get_scope_rejects_malformed_id(svc: CampaignApplicationService) -> None:
    with pytest.raises(ApplicationValidationError):
        await svc.get_scope("not-a-uuid")


async def test_get_is_scope_isolated(svc: CampaignApplicationService, tenant: TenantId) -> None:
    dto = await _observe(svc, tenant)
    assert (
        await svc.get(GetCampaignQuery(tenant_id=tenant, campaign_id=dto.campaign_id))
    ).campaign_id
    with pytest.raises(ApplicationNotFoundError):
        await svc.get(GetCampaignQuery(tenant_id=TenantId.generate(), campaign_id=dto.campaign_id))
    with pytest.raises(ApplicationNotFoundError):
        await svc.get(GetCampaignQuery(tenant_id=None, campaign_id=dto.campaign_id))


async def test_list_is_scope_isolated(svc: CampaignApplicationService, tenant: TenantId) -> None:
    await _observe(svc, tenant, "Cloud Hopper")
    await _observe(svc, None, "Operation Aurora")
    tenant_items = await svc.list(ListCampaignsQuery(tenant_id=tenant))
    global_items = await svc.list(ListCampaignsQuery(tenant_id=None))
    assert [i.canonical_name for i in tenant_items] == ["cloud hopper"]
    assert [i.canonical_name for i in global_items] == ["operation aurora"]


async def test_list_filters_by_all_four_dimensions(svc: CampaignApplicationService) -> None:
    espionage = await _observe(
        svc,
        None,
        "Cloud Hopper",
        status="ongoing",
        motivation="espionage",
        target_sectors=("technology",),
    )
    await _observe(
        svc,
        None,
        "Carbanak",
        status="concluded",
        motivation="financial",
        target_sectors=("finance",),
    )

    by_status = await svc.list(ListCampaignsQuery(tenant_id=None, status="ongoing"))
    assert [i.canonical_name for i in by_status] == ["cloud hopper"]

    by_motivation = await svc.list(ListCampaignsQuery(tenant_id=None, motivation="financial"))
    assert [i.canonical_name for i in by_motivation] == ["carbanak"]

    by_sector = await svc.list(ListCampaignsQuery(tenant_id=None, target_sector="technology"))
    assert [i.canonical_name for i in by_sector] == ["cloud hopper"]

    await svc.deprecate(
        DeprecateCampaignCommand(
            tenant_id=None, campaign_id=espionage.campaign_id, evidence=ATTRIBUTION
        )
    )
    deprecated = await svc.list(ListCampaignsQuery(tenant_id=None, lifecycle_status="deprecated"))
    assert [i.canonical_name for i in deprecated] == ["cloud hopper"]


async def test_lifecycle_and_status_filters_are_independent(
    svc: CampaignApplicationService,
) -> None:
    """A concluded campaign whose record is still active must appear
    under status=concluded AND lifecycle_status=active."""
    await _observe(svc, None, "Carbanak", status="concluded")
    concluded = await svc.list(ListCampaignsQuery(tenant_id=None, status="concluded"))
    still_active = await svc.list(ListCampaignsQuery(tenant_id=None, lifecycle_status="active"))
    assert [i.canonical_name for i in concluded] == ["carbanak"]
    assert [i.canonical_name for i in still_active] == ["carbanak"]


async def test_list_rejects_invalid_filter_values(svc: CampaignApplicationService) -> None:
    for query in (
        ListCampaignsQuery(tenant_id=None, lifecycle_status="bogus"),
        ListCampaignsQuery(tenant_id=None, status="paused"),
        ListCampaignsQuery(tenant_id=None, motivation="curiosity"),
        ListCampaignsQuery(tenant_id=None, target_sector="aerospace"),
    ):
        with pytest.raises(ApplicationValidationError):
            await svc.list(query)


async def test_list_query_validates_pagination_bounds() -> None:
    with pytest.raises(ApplicationValidationError):
        ListCampaignsQuery(tenant_id=None, limit=0)
    with pytest.raises(ApplicationValidationError):
        ListCampaignsQuery(tenant_id=None, limit=MAX_LIST_LIMIT + 1)
    with pytest.raises(ApplicationValidationError):
        ListCampaignsQuery(tenant_id=None, offset=-1)


async def test_list_paginates(svc: CampaignApplicationService) -> None:
    for i in range(5):
        await _observe(svc, None, f"campaign {i}")
    page = await svc.list(ListCampaignsQuery(tenant_id=None, limit=2, offset=0))
    assert len(page) == 2


async def test_summary_dto_carries_counts(svc: CampaignApplicationService) -> None:
    await _observe(
        svc,
        None,
        "Cloud Hopper",
        aliases=("APT10",),
        objectives=(ObjectiveInput(objective_type="espionage"),),
        regions=("EU",),
        target_sectors=("technology",),
    )
    summary = (await svc.list(ListCampaignsQuery(tenant_id=None)))[0]
    assert (
        summary.alias_count,
        summary.objective_count,
        summary.region_count,
        summary.target_sector_count,
    ) == (1, 1, 1, 1)


# ── Enrichment ──────────────────────────────────────────────────────────


async def test_add_alias_persists_and_publishes(
    svc: CampaignApplicationService, events: RecordingEventPublisher
) -> None:
    dto = await _observe(svc, None)
    updated = await svc.add_alias(
        AddAliasCommand(tenant_id=None, campaign_id=dto.campaign_id, alias="APT10")
    )
    assert updated.aliases == ("APT10",)
    assert len(updated.version_history) == 2
    assert isinstance(events.all_published[-1], AliasAdded)


async def test_add_objective_region_and_target_sector(svc: CampaignApplicationService) -> None:
    dto = await _observe(svc, None)
    await svc.add_objective(
        AddObjectiveCommand(
            tenant_id=None,
            campaign_id=dto.campaign_id,
            objective=ObjectiveInput(objective_type="disruption", description="d"),
        )
    )
    await svc.add_region(
        AddRegionCommand(tenant_id=None, campaign_id=dto.campaign_id, region="apac")
    )
    updated = await svc.add_target_sector(
        AddTargetSectorCommand(tenant_id=None, campaign_id=dto.campaign_id, target_sector="energy")
    )
    assert updated.objectives[0].objective_type == "disruption"
    assert updated.regions == ("APAC",)
    assert updated.target_sectors == ("energy",)


async def test_add_target_sector_rejects_unknown_value(svc: CampaignApplicationService) -> None:
    dto = await _observe(svc, None)
    with pytest.raises(ApplicationValidationError):
        await svc.add_target_sector(
            AddTargetSectorCommand(
                tenant_id=None, campaign_id=dto.campaign_id, target_sector="aerospace"
            )
        )


async def test_add_evidence_citation_and_source_attribution(
    svc: CampaignApplicationService,
) -> None:
    dto = await _observe(svc, None)
    await svc.add_evidence_citation(
        AddEvidenceCitationCommand(
            tenant_id=None, campaign_id=dto.campaign_id, citation="https://example.test/r"
        )
    )
    updated = await svc.add_source_attribution(
        AddSourceAttributionCommand(
            tenant_id=None, campaign_id=dto.campaign_id, attribution=ATTRIBUTION
        )
    )
    assert updated.evidence_citations == ("https://example.test/r",)
    assert updated.source_attributions[0].confidence == "high"
    assert len(updated.version_history) == 3


async def test_enrichment_is_scope_isolated(
    svc: CampaignApplicationService, tenant: TenantId
) -> None:
    dto = await _observe(svc, tenant)
    with pytest.raises(ApplicationNotFoundError):
        await svc.add_alias(
            AddAliasCommand(tenant_id=TenantId.generate(), campaign_id=dto.campaign_id, alias="x")
        )


# ── Real-world status axis ──────────────────────────────────────────────


async def test_transition_status_moves_real_world_state(
    svc: CampaignApplicationService, events: RecordingEventPublisher
) -> None:
    dto = await _observe(svc, None)
    updated = await svc.transition_status(
        TransitionCampaignStatusCommand(
            tenant_id=None,
            campaign_id=dto.campaign_id,
            target_status="ongoing",
            evidence=ATTRIBUTION,
        )
    )
    assert updated.status == "ongoing"
    assert updated.lifecycle_status == "active"
    assert isinstance(events.all_published[-1], StatusTransitioned)


async def test_illegal_status_transition_raises(svc: CampaignApplicationService) -> None:
    dto = await _observe(svc, None)
    await svc.transition_status(
        TransitionCampaignStatusCommand(
            tenant_id=None,
            campaign_id=dto.campaign_id,
            target_status="concluded",
            evidence=ATTRIBUTION,
        )
    )
    with pytest.raises(InvalidStatusTransitionError):
        await svc.transition_status(
            TransitionCampaignStatusCommand(
                tenant_id=None,
                campaign_id=dto.campaign_id,
                target_status="ongoing",
                evidence=ATTRIBUTION,
            )
        )


async def test_transition_status_rejects_unknown_target(svc: CampaignApplicationService) -> None:
    dto = await _observe(svc, None)
    with pytest.raises(ApplicationValidationError):
        await svc.transition_status(
            TransitionCampaignStatusCommand(
                tenant_id=None,
                campaign_id=dto.campaign_id,
                target_status="paused",
                evidence=ATTRIBUTION,
            )
        )


# ── Record lifecycle axis ───────────────────────────────────────────────


async def test_deprecate_revoke_supersede_reactivate(
    svc: CampaignApplicationService, events: RecordingEventPublisher
) -> None:
    dto = await _observe(svc, None)
    deprecated = await svc.deprecate(
        DeprecateCampaignCommand(tenant_id=None, campaign_id=dto.campaign_id, evidence=ATTRIBUTION)
    )
    assert deprecated.lifecycle_status == "deprecated"
    assert isinstance(events.all_published[-1], CampaignDeprecated)

    reactivated = await svc.reactivate(
        ReactivateCampaignCommand(tenant_id=None, campaign_id=dto.campaign_id, evidence=ATTRIBUTION)
    )
    assert reactivated.lifecycle_status == "active"

    successor = await _observe(svc, None, "Cloud Hopper NG")
    superseded = await svc.supersede(
        SupersedeCampaignCommand(
            tenant_id=None,
            campaign_id=dto.campaign_id,
            superseded_by=successor.campaign_id,
            evidence=ATTRIBUTION,
        )
    )
    assert superseded.lifecycle_status == "superseded"
    assert superseded.superseded_by == successor.campaign_id

    revoked = await svc.revoke(
        RevokeCampaignCommand(tenant_id=None, campaign_id=dto.campaign_id, evidence=ATTRIBUTION)
    )
    assert revoked.lifecycle_status == "revoked"


async def test_record_lifecycle_does_not_change_real_world_status(
    svc: CampaignApplicationService,
) -> None:
    dto = await _observe(svc, None, status="ongoing")
    deprecated = await svc.deprecate(
        DeprecateCampaignCommand(tenant_id=None, campaign_id=dto.campaign_id, evidence=ATTRIBUTION)
    )
    assert deprecated.status == "ongoing"
    assert deprecated.lifecycle_status == "deprecated"


async def test_illegal_lifecycle_transition_raises(svc: CampaignApplicationService) -> None:
    dto = await _observe(svc, None)
    await svc.revoke(
        RevokeCampaignCommand(tenant_id=None, campaign_id=dto.campaign_id, evidence=ATTRIBUTION)
    )
    with pytest.raises(InvalidLifecycleTransitionError):
        await svc.deprecate(
            DeprecateCampaignCommand(
                tenant_id=None, campaign_id=dto.campaign_id, evidence=ATTRIBUTION
            )
        )


async def test_lifecycle_on_missing_record_raises(svc: CampaignApplicationService) -> None:
    with pytest.raises(ApplicationNotFoundError):
        await svc.deprecate(
            DeprecateCampaignCommand(tenant_id=None, campaign_id=str(uuid4()), evidence=ATTRIBUTION)
        )


async def test_events_not_published_when_commit_fails(
    repo: InMemoryCampaignRepository, events: RecordingEventPublisher
) -> None:
    failing = FakeUnitOfWork(repo, fail_commit=True)
    svc = CampaignApplicationService(uow_factory=lambda: failing, event_publisher=events)
    with pytest.raises(RuntimeError, match="simulated commit failure"):
        await _observe(svc, None)
    assert events.all_published == []
    assert failing.rolled_back
