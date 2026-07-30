from __future__ import annotations

from datetime import UTC, datetime

from risk_engine.domain.entities.risk_contribution import RiskContribution
from risk_engine.domain.events.risk_profile_events import RiskProfileCreated
from risk_engine.domain.factories.risk_profile_factory import RiskProfileFactory
from risk_engine.domain.value_objects.enums import RiskDimension, RiskScale, RiskSignalType
from risk_engine.domain.value_objects.identifiers import RiskProfileId, TenantId
from risk_engine.domain.value_objects.normalized_score import NormalizedRiskScore
from risk_engine.domain.value_objects.risk_signal import RiskSignalReference

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _contribution(tenant_id: TenantId) -> RiskContribution:
    signal = RiskSignalReference(
        tenant_id=tenant_id,
        source_context="vulnerability_engine",
        source_aggregate_type="AssetVulnerability",
        source_id="abc",
        signal_type=RiskSignalType.SEVERITY_RATING,
        raw_value=5.0,
        raw_scale=RiskScale.CVSS_0_10,
        observed_at=NOW,
    )
    return RiskContribution(
        dimension=RiskDimension.VULNERABILITY,
        normalized_score=NormalizedRiskScore(5.0),
        source_signal=signal,
        computed_at=NOW,
    )


def test_create_yields_profile_with_one_contribution_and_no_composite_score(
    tenant_id: TenantId,
) -> None:
    profile = RiskProfileFactory.create(
        tenant_id=tenant_id,
        subject_reference="asset-1",
        initial_contribution=_contribution(tenant_id),
        now=NOW,
    )
    assert len(profile.contributions) == 1
    assert profile.composite_score is None
    assert profile.subject_reference == "asset-1"
    assert profile.tenant_id == tenant_id


def test_create_pending_events_contain_risk_profile_created(tenant_id: TenantId) -> None:
    profile = RiskProfileFactory.create(
        tenant_id=tenant_id,
        subject_reference="asset-1",
        initial_contribution=_contribution(tenant_id),
        now=NOW,
    )
    events = profile.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], RiskProfileCreated)
    assert events[0].aggregate_type == "EnterpriseRiskProfile"
    assert events[0].tenant_id == str(tenant_id)


def test_create_accepts_explicit_profile_id(tenant_id: TenantId) -> None:
    explicit_id = RiskProfileId.generate()
    profile = RiskProfileFactory.create(
        tenant_id=tenant_id,
        subject_reference="asset-1",
        initial_contribution=_contribution(tenant_id),
        now=NOW,
        profile_id=explicit_id,
    )
    assert profile.profile_id == explicit_id
