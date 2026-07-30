from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from risk_engine.domain.entities.risk_contribution import RiskContribution
from risk_engine.domain.events.risk_profile_events import (
    RiskProfileAccepted,
    RiskProfileAcknowledged,
    RiskProfileClosed,
    RiskProfileCreated,
    RiskProfileMitigated,
    RiskProfileScoreRecomputed,
    RiskProfileStatusChanged,
)
from risk_engine.domain.exceptions.domain_exceptions import (
    EmptyContributionsError,
    InvalidRiskProfileTransition,
    TenantMismatch,
)
from risk_engine.domain.factories.risk_profile_factory import RiskProfileFactory
from risk_engine.domain.value_objects.composite_score import CompositeRiskScore
from risk_engine.domain.value_objects.enums import (
    RiskDimension,
    RiskProfileStatus,
    RiskScale,
    RiskSignalType,
)
from risk_engine.domain.value_objects.identifiers import TenantId
from risk_engine.domain.value_objects.normalized_score import NormalizedRiskScore
from risk_engine.domain.value_objects.risk_signal import RiskSignalReference

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def make_contribution(tenant_id: TenantId) -> RiskContribution:
    signal = RiskSignalReference(
        tenant_id=tenant_id,
        source_context="vulnerability_engine",
        source_aggregate_type="AssetVulnerability",
        source_id="corr-1",
        signal_type=RiskSignalType.SEVERITY_RATING,
        raw_value=7.5,
        raw_scale=RiskScale.CVSS_0_10,
        observed_at=NOW,
        subject_reference="asset-1",
    )
    return RiskContribution(
        dimension=RiskDimension.VULNERABILITY,
        normalized_score=NormalizedRiskScore(7.5),
        source_signal=signal,
        computed_at=NOW,
    )


def _create(tenant_id: TenantId):
    return RiskProfileFactory.create(
        tenant_id=tenant_id,
        subject_reference="asset-1",
        initial_contribution=make_contribution(tenant_id),
        now=NOW,
    )


def test_factory_creates_open_profile_and_emits_created_event(tenant_id: TenantId) -> None:
    profile = _create(tenant_id)
    assert profile.status == RiskProfileStatus.OPEN
    assert profile.composite_score is None
    assert len(profile.contributions) == 1
    events = profile.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], RiskProfileCreated)
    assert events[0].subject_reference == "asset-1"


def test_recompute_score_updates_state_and_emits_event(tenant_id: TenantId) -> None:
    profile = _create(tenant_id)
    profile.pop_events()
    composite = CompositeRiskScore(
        value=NormalizedRiskScore(6.0), weight_profile_id="default:v1", computed_at=NOW
    )
    contributions = (make_contribution(tenant_id),)
    profile.recompute_score(tenant_id, composite, contributions, NOW + timedelta(hours=1))
    assert profile.composite_score is composite
    events = profile.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], RiskProfileScoreRecomputed)
    assert events[0].composite_score is composite


def test_recompute_score_rejects_empty_contributions(tenant_id: TenantId) -> None:
    profile = _create(tenant_id)
    composite = CompositeRiskScore(
        value=NormalizedRiskScore(6.0), weight_profile_id="default:v1", computed_at=NOW
    )
    with pytest.raises(EmptyContributionsError):
        profile.recompute_score(tenant_id, composite, (), NOW)


def test_recompute_score_rejects_wrong_tenant(tenant_id: TenantId) -> None:
    profile = _create(tenant_id)
    composite = CompositeRiskScore(
        value=NormalizedRiskScore(6.0), weight_profile_id="default:v1", computed_at=NOW
    )
    with pytest.raises(TenantMismatch):
        profile.recompute_score(
            TenantId.generate(), composite, (make_contribution(tenant_id),), NOW
        )


def test_acknowledge_from_open_emits_two_events(tenant_id: TenantId) -> None:
    profile = _create(tenant_id)
    profile.pop_events()
    profile.acknowledge(tenant_id, NOW)
    assert profile.status == RiskProfileStatus.ACKNOWLEDGED
    events = profile.pop_events()
    kinds = {type(e) for e in events}
    assert RiskProfileStatusChanged in kinds
    assert RiskProfileAcknowledged in kinds


def test_acknowledge_twice_is_illegal(tenant_id: TenantId) -> None:
    profile = _create(tenant_id)
    profile.acknowledge(tenant_id, NOW)
    with pytest.raises(InvalidRiskProfileTransition):
        profile.acknowledge(tenant_id, NOW)


def test_mitigate_from_open_or_acknowledged(tenant_id: TenantId) -> None:
    profile = _create(tenant_id)
    profile.mitigate(tenant_id, NOW)
    assert profile.status == RiskProfileStatus.MITIGATED
    events = profile.pop_events()
    assert any(isinstance(e, RiskProfileMitigated) for e in events)


def test_mitigate_from_closed_is_illegal(tenant_id: TenantId) -> None:
    profile = _create(tenant_id)
    profile.close(tenant_id, NOW)
    with pytest.raises(InvalidRiskProfileTransition):
        profile.mitigate(tenant_id, NOW)


def test_accept_sets_expiry_and_emits_events(tenant_id: TenantId) -> None:
    profile = _create(tenant_id)
    profile.pop_events()
    expires_at = NOW + timedelta(days=30)
    profile.accept(tenant_id, expires_at, NOW)
    assert profile.status == RiskProfileStatus.ACCEPTED
    assert profile.accepted_expires_at == expires_at
    events = profile.pop_events()
    assert any(isinstance(e, RiskProfileAccepted) for e in events)


def test_close_from_any_non_terminal_state(tenant_id: TenantId) -> None:
    profile = _create(tenant_id)
    profile.close(tenant_id, NOW)
    assert profile.status == RiskProfileStatus.CLOSED
    events = profile.pop_events()
    assert any(isinstance(e, RiskProfileClosed) for e in events)


def test_close_twice_is_illegal(tenant_id: TenantId) -> None:
    profile = _create(tenant_id)
    profile.close(tenant_id, NOW)
    with pytest.raises(InvalidRiskProfileTransition):
        profile.close(tenant_id, NOW)


def test_tenant_mismatch_raised_on_status_methods(tenant_id: TenantId) -> None:
    profile = _create(tenant_id)
    other = TenantId.generate()
    with pytest.raises(TenantMismatch):
        profile.acknowledge(other, NOW)
