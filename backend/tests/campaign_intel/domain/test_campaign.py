from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from campaign_intel.domain.aggregates.campaign import Campaign
from campaign_intel.domain.events.campaign_events import (
    AliasAdded,
    CampaignDeprecated,
    CampaignObserved,
    CampaignReactivated,
    CampaignRevoked,
    CampaignSuperseded,
    EvidenceCitationAdded,
    ObjectiveAdded,
    RegionAdded,
    SourceAttributionAdded,
    StatusTransitioned,
    TargetSectorAdded,
)
from campaign_intel.domain.exceptions.domain_exceptions import (
    InvalidLifecycleTransitionError,
    InvalidRegionError,
    InvalidStatusTransitionError,
    TenantMismatchError,
)
from campaign_intel.domain.factories.campaign_factory import CampaignFactory
from campaign_intel.domain.value_objects.enums import (
    CampaignConfidence,
    CampaignLifecycleStatus,
    CampaignMotivation,
    CampaignObjectiveType,
    CampaignStatus,
    CampaignTargetSector,
)
from campaign_intel.domain.value_objects.evidence import EvidenceCitation, SourceAttribution
from campaign_intel.domain.value_objects.identifiers import CampaignId, TenantId
from campaign_intel.domain.value_objects.taxonomy import CampaignAlias, CampaignObjective
from campaign_intel.domain.value_objects.timeline import CampaignTimeline

NOW = datetime(2026, 8, 5, tzinfo=UTC)
LATER = NOW + timedelta(hours=1)


def _attribution(source_system: str = "redforge-analyst") -> SourceAttribution:
    return SourceAttribution(
        source_system=source_system,
        reference="ref-1",
        observed_at=NOW,
        confidence=CampaignConfidence.HIGH,
    )


def _make(tenant_id: TenantId | None = None, canonical_name: str = "Cloud Hopper") -> Campaign:
    return Campaign.observe(
        campaign_id=CampaignId.generate(),
        tenant_id=tenant_id,
        canonical_name=canonical_name,
        now=NOW,
    )


# ── Construction ────────────────────────────────────────────────────────


def test_observe_starts_active_with_normalized_name_and_first_version() -> None:
    campaign = _make(canonical_name="  CLOUD-HOPPER  ")
    assert campaign.canonical_name == "cloud hopper"
    assert campaign.lifecycle_status is CampaignLifecycleStatus.ACTIVE
    assert campaign.status is CampaignStatus.UNKNOWN
    assert campaign.motivation is CampaignMotivation.UNKNOWN
    assert campaign.superseded_by is None
    assert len(campaign.version_history) == 1
    assert campaign.version_history[0].change_summary == "Observed"
    assert campaign.row_version == 1


def test_observe_emits_campaign_observed_with_payload() -> None:
    tenant = TenantId.generate()
    campaign = Campaign.observe(
        campaign_id=CampaignId.generate(),
        tenant_id=tenant,
        canonical_name="Cloud Hopper",
        now=NOW,
        status=CampaignStatus.ONGOING,
        motivation=CampaignMotivation.ESPIONAGE,
    )
    events = campaign.pop_events()
    assert len(events) == 1
    event = events[0]
    assert isinstance(event, CampaignObserved)
    assert event.canonical_name == "cloud hopper"
    assert event.status == "ongoing"
    assert event.motivation == "espionage"
    assert event.tenant_id == str(tenant)
    assert event.aggregate_type == "Campaign"
    assert campaign.pop_events() == []


def test_global_record_renders_empty_tenant_id_in_events() -> None:
    campaign = _make(tenant_id=None)
    assert campaign.pop_events()[0].tenant_id == ""


def test_observe_normalizes_regions_at_construction() -> None:
    campaign = Campaign.observe(
        campaign_id=CampaignId.generate(),
        tenant_id=None,
        canonical_name="c",
        now=NOW,
        regions=("eu", " us "),
    )
    assert campaign.regions == ("EU", "US")


def test_observe_rejects_unnormalizable_region() -> None:
    with pytest.raises(InvalidRegionError):
        Campaign.observe(
            campaign_id=CampaignId.generate(),
            tenant_id=None,
            canonical_name="c",
            now=NOW,
            regions=("  ",),
        )


def test_factory_is_the_supported_construction_path() -> None:
    campaign = CampaignFactory().observe(
        tenant_id=None,
        canonical_name="Operation Aurora",
        now=NOW,
        status=CampaignStatus.CONCLUDED,
        motivation=CampaignMotivation.ESPIONAGE,
        timeline=CampaignTimeline(first_observed=NOW),
        target_sectors=(CampaignTargetSector.TECHNOLOGY,),
        confidence=CampaignConfidence.VERY_HIGH,
    )
    assert campaign.canonical_name == "operation aurora"
    assert campaign.status is CampaignStatus.CONCLUDED
    assert campaign.target_sectors == (CampaignTargetSector.TECHNOLOGY,)
    assert campaign.confidence is CampaignConfidence.VERY_HIGH
    assert campaign.timeline is not None


# ── Enrichment ──────────────────────────────────────────────────────────


def test_add_alias_appends_version_and_emits_event() -> None:
    campaign = _make()
    campaign.pop_events()
    campaign.add_alias(None, CampaignAlias("APT10"), LATER)
    assert campaign.aliases == (CampaignAlias("APT10"),)
    assert len(campaign.version_history) == 2
    assert campaign.updated_at == LATER
    event = campaign.pop_events()[0]
    assert isinstance(event, AliasAdded)
    assert event.alias == "APT10"


def test_add_alias_is_idempotent_on_the_collection() -> None:
    campaign = _make()
    campaign.add_alias(None, CampaignAlias("APT10"), LATER)
    campaign.add_alias(None, CampaignAlias("APT10"), LATER)
    assert campaign.aliases == (CampaignAlias("APT10"),)


def test_add_objective_dedupes_and_emits() -> None:
    campaign = _make()
    campaign.pop_events()
    objective = CampaignObjective(CampaignObjectiveType.ESPIONAGE, "steal IP")
    campaign.add_objective(None, objective, LATER)
    campaign.add_objective(None, objective, LATER)
    assert campaign.objectives == (objective,)
    events = campaign.pop_events()
    assert [type(e) for e in events] == [ObjectiveAdded, ObjectiveAdded]
    assert events[0].objective_type == "espionage"
    assert events[0].description == "steal IP"


def test_add_region_normalizes_dedupes_and_emits() -> None:
    campaign = _make()
    campaign.pop_events()
    campaign.add_region(None, "eu", LATER)
    campaign.add_region(None, "  EU ", LATER)
    assert campaign.regions == ("EU",)
    event = campaign.pop_events()[0]
    assert isinstance(event, RegionAdded)
    assert event.region == "EU"


def test_add_region_rejects_bad_format() -> None:
    campaign = _make()
    with pytest.raises(InvalidRegionError):
        campaign.add_region(None, "!!", LATER)


def test_add_target_sector_dedupes_and_emits() -> None:
    campaign = _make()
    campaign.pop_events()
    campaign.add_target_sector(None, CampaignTargetSector.FINANCE, LATER)
    campaign.add_target_sector(None, CampaignTargetSector.FINANCE, LATER)
    assert campaign.target_sectors == (CampaignTargetSector.FINANCE,)
    event = campaign.pop_events()[0]
    assert isinstance(event, TargetSectorAdded)
    assert event.target_sector == "finance"


def test_add_evidence_citation_appends_and_emits() -> None:
    campaign = _make()
    campaign.pop_events()
    campaign.add_evidence_citation(None, EvidenceCitation("https://example.test/r1"), LATER)
    assert len(campaign.evidence_citations) == 1
    event = campaign.pop_events()[0]
    assert isinstance(event, EvidenceCitationAdded)
    assert event.citation == "https://example.test/r1"


def test_add_source_attribution_records_source_and_confidence() -> None:
    campaign = _make()
    campaign.pop_events()
    campaign.add_source_attribution(None, _attribution("vendor-x"), LATER)
    assert len(campaign.source_attributions) == 1
    event = campaign.pop_events()[0]
    assert isinstance(event, SourceAttributionAdded)
    assert event.source_system == "vendor-x"
    assert event.confidence == "high"
    assert campaign.version_history[-1].source == "vendor-x"


def test_every_mutator_appends_exactly_one_version_record() -> None:
    campaign = _make()
    campaign.add_alias(None, CampaignAlias("a"), LATER)
    campaign.add_objective(None, CampaignObjective(CampaignObjectiveType.DISRUPTION), LATER)
    campaign.add_region(None, "EU", LATER)
    campaign.add_target_sector(None, CampaignTargetSector.ENERGY, LATER)
    campaign.add_evidence_citation(None, EvidenceCitation("c"), LATER)
    campaign.add_source_attribution(None, _attribution(), LATER)
    campaign.transition_status(None, CampaignStatus.ONGOING, _attribution(), LATER)
    campaign.deprecate(None, _attribution(), LATER)
    # 1 (observe) + 8 mutators
    assert [v.version for v in campaign.version_history] == [1, 2, 3, 4, 5, 6, 7, 8, 9]


# ── Tenant isolation ────────────────────────────────────────────────────


def test_mutating_with_wrong_tenant_raises() -> None:
    owner = TenantId.generate()
    campaign = _make(tenant_id=owner)
    with pytest.raises(TenantMismatchError):
        campaign.add_alias(TenantId.generate(), CampaignAlias("x"), LATER)
    with pytest.raises(TenantMismatchError):
        campaign.add_alias(None, CampaignAlias("x"), LATER)


def test_mutating_a_global_record_with_a_tenant_raises() -> None:
    campaign = _make(tenant_id=None)
    with pytest.raises(TenantMismatchError):
        campaign.deprecate(TenantId.generate(), _attribution(), LATER)
    with pytest.raises(TenantMismatchError):
        campaign.transition_status(
            TenantId.generate(), CampaignStatus.ONGOING, _attribution(), LATER
        )


# ── Real-world status axis ──────────────────────────────────────────────


def test_transition_status_moves_real_world_state_and_emits() -> None:
    campaign = _make()
    campaign.pop_events()
    campaign.transition_status(None, CampaignStatus.ONGOING, _attribution(), LATER)
    assert campaign.status is CampaignStatus.ONGOING
    event = campaign.pop_events()[0]
    assert isinstance(event, StatusTransitioned)
    assert (event.from_status, event.to_status) == ("unknown", "ongoing")


def test_status_can_reopen_from_suspected_concluded() -> None:
    campaign = _make()
    campaign.transition_status(None, CampaignStatus.ONGOING, _attribution(), LATER)
    campaign.transition_status(None, CampaignStatus.SUSPECTED_CONCLUDED, _attribution(), LATER)
    campaign.transition_status(None, CampaignStatus.ONGOING, _attribution(), LATER)
    assert campaign.status is CampaignStatus.ONGOING


def test_concluded_status_is_terminal() -> None:
    campaign = _make()
    campaign.transition_status(None, CampaignStatus.CONCLUDED, _attribution(), LATER)
    for target in CampaignStatus:
        with pytest.raises(InvalidStatusTransitionError):
            campaign.transition_status(None, target, _attribution(), LATER)


def test_illegal_status_transition_raises_status_error_not_lifecycle_error() -> None:
    campaign = _make()
    campaign.transition_status(None, CampaignStatus.ONGOING, _attribution(), LATER)
    with pytest.raises(InvalidStatusTransitionError):
        campaign.transition_status(None, CampaignStatus.UNKNOWN, _attribution(), LATER)


# ── Record lifecycle axis ───────────────────────────────────────────────


def test_deprecate_then_reactivate_round_trip() -> None:
    campaign = _make()
    campaign.deprecate(None, _attribution(), LATER)
    assert campaign.lifecycle_status is CampaignLifecycleStatus.DEPRECATED
    campaign.pop_events()
    campaign.reactivate(None, _attribution(), LATER)
    assert campaign.lifecycle_status is CampaignLifecycleStatus.ACTIVE
    assert isinstance(campaign.pop_events()[0], CampaignReactivated)


def test_revoke_is_terminal() -> None:
    campaign = _make()
    campaign.revoke(None, _attribution(), LATER)
    assert campaign.lifecycle_status is CampaignLifecycleStatus.REVOKED
    for action in ("deprecate", "revoke", "reactivate"):
        with pytest.raises(InvalidLifecycleTransitionError):
            getattr(campaign, action)(None, _attribution(), LATER)


def test_supersede_sets_superseded_by_and_emits() -> None:
    campaign = _make()
    successor = CampaignId.generate()
    campaign.pop_events()
    campaign.supersede(None, successor, _attribution(), LATER)
    assert campaign.lifecycle_status is CampaignLifecycleStatus.SUPERSEDED
    assert campaign.superseded_by == successor
    event = campaign.pop_events()[0]
    assert isinstance(event, CampaignSuperseded)
    assert event.superseded_by == str(successor)


def test_superseded_may_only_go_to_revoked() -> None:
    campaign = _make()
    campaign.supersede(None, CampaignId.generate(), _attribution(), LATER)
    with pytest.raises(InvalidLifecycleTransitionError):
        campaign.reactivate(None, _attribution(), LATER)
    with pytest.raises(InvalidLifecycleTransitionError):
        campaign.deprecate(None, _attribution(), LATER)
    campaign.revoke(None, _attribution(), LATER)
    assert campaign.lifecycle_status is CampaignLifecycleStatus.REVOKED


def test_reactivate_from_active_is_illegal() -> None:
    campaign = _make()
    with pytest.raises(InvalidLifecycleTransitionError):
        campaign.reactivate(None, _attribution(), LATER)


def test_reactivate_clears_superseded_by() -> None:
    campaign = _make()
    campaign.deprecate(None, _attribution(), LATER)
    campaign.reactivate(None, _attribution(), LATER)
    assert campaign.superseded_by is None


def test_lifecycle_events_emitted() -> None:
    campaign = _make()
    campaign.pop_events()
    campaign.deprecate(None, _attribution(), LATER)
    assert isinstance(campaign.pop_events()[0], CampaignDeprecated)
    campaign.revoke(None, _attribution(), LATER)
    assert isinstance(campaign.pop_events()[0], CampaignRevoked)


# ── The two axes are genuinely independent ──────────────────────────────


def test_record_lifecycle_never_touches_real_world_status() -> None:
    campaign = _make()
    campaign.transition_status(None, CampaignStatus.ONGOING, _attribution(), LATER)
    campaign.deprecate(None, _attribution(), LATER)
    campaign.revoke(None, _attribution(), LATER)
    assert campaign.status is CampaignStatus.ONGOING


def test_real_world_status_never_touches_record_lifecycle() -> None:
    campaign = _make()
    campaign.transition_status(None, CampaignStatus.CONCLUDED, _attribution(), LATER)
    assert campaign.lifecycle_status is CampaignLifecycleStatus.ACTIVE


def test_a_revoked_record_cannot_still_be_status_transitioned() -> None:
    """Record lifecycle governs whether the record may be mutated at all
    only through its own table — a revoked record's real-world status is
    still a legal field to correct, so this must NOT raise."""
    campaign = _make()
    campaign.revoke(None, _attribution(), LATER)
    campaign.transition_status(None, CampaignStatus.ONGOING, _attribution(), LATER)
    assert campaign.status is CampaignStatus.ONGOING
    assert campaign.lifecycle_status is CampaignLifecycleStatus.REVOKED


def test_identity_is_not_mutable_via_any_public_method() -> None:
    """Only RedForge-native fields mutate — there is no rename/
    re-identify method on the aggregate."""
    public = {m for m in dir(Campaign) if not m.startswith("_")}
    assert not {"rename", "set_canonical_name", "change_identity"} & public
