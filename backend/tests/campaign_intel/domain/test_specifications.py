from __future__ import annotations

from datetime import UTC, datetime

from campaign_intel.domain.aggregates.campaign import Campaign
from campaign_intel.domain.specifications.campaign_specifications import (
    ActiveCampaignSpecification,
    ConcludedCampaignSpecification,
    DeprecatedOrRevokedCampaignSpecification,
    IsGlobalCampaignSpecification,
    IsTenantCampaignSpecification,
    OngoingCampaignSpecification,
    SupersededCampaignSpecification,
)
from campaign_intel.domain.value_objects.enums import CampaignConfidence, CampaignStatus
from campaign_intel.domain.value_objects.evidence import SourceAttribution
from campaign_intel.domain.value_objects.identifiers import CampaignId, TenantId

NOW = datetime(2026, 8, 5, tzinfo=UTC)
EVIDENCE = SourceAttribution(
    source_system="s", reference="r", observed_at=NOW, confidence=CampaignConfidence.HIGH
)


def _make(tenant_id: TenantId | None = None) -> Campaign:
    return Campaign.observe(
        campaign_id=CampaignId.generate(),
        tenant_id=tenant_id,
        canonical_name="cloud hopper",
        now=NOW,
    )


def test_active_specification_reads_record_lifecycle() -> None:
    spec = ActiveCampaignSpecification()
    campaign = _make()
    assert spec.is_satisfied_by(campaign)
    campaign.deprecate(None, EVIDENCE, NOW)
    assert not spec.is_satisfied_by(campaign)


def test_deprecated_or_revoked_specification() -> None:
    spec = DeprecatedOrRevokedCampaignSpecification()
    active = _make()
    assert not spec.is_satisfied_by(active)

    deprecated = _make()
    deprecated.deprecate(None, EVIDENCE, NOW)
    assert spec.is_satisfied_by(deprecated)

    revoked = _make()
    revoked.revoke(None, EVIDENCE, NOW)
    assert spec.is_satisfied_by(revoked)


def test_deprecated_or_revoked_excludes_superseded() -> None:
    superseded = _make()
    superseded.supersede(None, CampaignId.generate(), EVIDENCE, NOW)
    assert not DeprecatedOrRevokedCampaignSpecification().is_satisfied_by(superseded)
    assert SupersededCampaignSpecification().is_satisfied_by(superseded)


def test_ongoing_specification_reads_real_world_status() -> None:
    spec = OngoingCampaignSpecification()
    campaign = _make()
    assert not spec.is_satisfied_by(campaign)
    campaign.transition_status(None, CampaignStatus.ONGOING, EVIDENCE, NOW)
    assert spec.is_satisfied_by(campaign)


def test_concluded_specification() -> None:
    campaign = _make()
    campaign.transition_status(None, CampaignStatus.CONCLUDED, EVIDENCE, NOW)
    assert ConcludedCampaignSpecification().is_satisfied_by(campaign)
    assert not OngoingCampaignSpecification().is_satisfied_by(campaign)


def test_the_two_axes_are_independently_satisfiable() -> None:
    """A concluded real-world campaign with a perfectly active record —
    the exact case a single conflated status field would make
    unrepresentable."""
    campaign = _make()
    campaign.transition_status(None, CampaignStatus.CONCLUDED, EVIDENCE, NOW)
    assert ConcludedCampaignSpecification().is_satisfied_by(campaign)
    assert ActiveCampaignSpecification().is_satisfied_by(campaign)

    # ...and the inverse: an ongoing campaign whose record is revoked.
    other = _make()
    other.transition_status(None, CampaignStatus.ONGOING, EVIDENCE, NOW)
    other.revoke(None, EVIDENCE, NOW)
    assert OngoingCampaignSpecification().is_satisfied_by(other)
    assert DeprecatedOrRevokedCampaignSpecification().is_satisfied_by(other)


def test_scope_specifications() -> None:
    tenant_owned = _make(TenantId.generate())
    global_owned = _make(None)
    assert IsTenantCampaignSpecification().is_satisfied_by(tenant_owned)
    assert not IsGlobalCampaignSpecification().is_satisfied_by(tenant_owned)
    assert IsGlobalCampaignSpecification().is_satisfied_by(global_owned)
    assert not IsTenantCampaignSpecification().is_satisfied_by(global_owned)
