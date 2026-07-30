from __future__ import annotations

from datetime import UTC, datetime, timedelta

from risk_engine.domain.entities.risk_contribution import RiskContribution
from risk_engine.domain.factories.risk_profile_factory import RiskProfileFactory
from risk_engine.domain.policies.risk_acceptance_expiry_policy import RiskAcceptanceExpiryPolicy
from risk_engine.domain.policies.risk_escalation_policy import RiskEscalationPolicy
from risk_engine.domain.specifications.risk_specifications import (
    IsCorrelatableSignalSpecification,
    IsCriticalRiskSpecification,
    IsStaleRiskProfileSpecification,
)
from risk_engine.domain.value_objects.composite_score import CompositeRiskScore
from risk_engine.domain.value_objects.enums import RiskDimension, RiskScale, RiskSignalType
from risk_engine.domain.value_objects.identifiers import TenantId
from risk_engine.domain.value_objects.normalized_score import NormalizedRiskScore
from risk_engine.domain.value_objects.risk_signal import RiskSignalReference

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _signal(tenant_id: TenantId, **overrides: object) -> RiskSignalReference:
    defaults: dict[str, object] = {
        "tenant_id": tenant_id,
        "source_context": "vulnerability_engine",
        "source_aggregate_type": "AssetVulnerability",
        "source_id": "abc",
        "signal_type": RiskSignalType.SEVERITY_RATING,
        "raw_value": 5.0,
        "raw_scale": RiskScale.CVSS_0_10,
        "observed_at": NOW,
        "subject_reference": "asset-1",
    }
    defaults.update(overrides)
    return RiskSignalReference(**defaults)  # type: ignore[arg-type]


def _contribution(tenant_id: TenantId) -> RiskContribution:
    return RiskContribution(
        dimension=RiskDimension.VULNERABILITY,
        normalized_score=NormalizedRiskScore(9.5),
        source_signal=_signal(tenant_id),
        computed_at=NOW,
    )


def _profile_with_score(tenant_id: TenantId, value: float, status_now: datetime = NOW):
    profile = RiskProfileFactory.create(
        tenant_id=tenant_id,
        subject_reference="asset-1",
        initial_contribution=_contribution(tenant_id),
        now=NOW,
    )
    composite = CompositeRiskScore(
        value=NormalizedRiskScore(value), weight_profile_id="default:v1", computed_at=status_now
    )
    profile.recompute_score(tenant_id, composite, (_contribution(tenant_id),), status_now)
    return profile


# --- RiskEscalationPolicy ---


def test_should_escalate_true_when_acknowledged_and_above_threshold(tenant_id: TenantId) -> None:
    profile = _profile_with_score(tenant_id, 9.0)
    profile.acknowledge(tenant_id, NOW)
    assert RiskEscalationPolicy.should_escalate(profile, NormalizedRiskScore(8.0)) is True


def test_should_escalate_false_when_open(tenant_id: TenantId) -> None:
    profile = _profile_with_score(tenant_id, 9.0)
    assert RiskEscalationPolicy.should_escalate(profile, NormalizedRiskScore(8.0)) is False


def test_should_escalate_false_when_closed(tenant_id: TenantId) -> None:
    profile = _profile_with_score(tenant_id, 9.0)
    profile.close(tenant_id, NOW)
    assert RiskEscalationPolicy.should_escalate(profile, NormalizedRiskScore(8.0)) is False


def test_should_escalate_false_below_threshold(tenant_id: TenantId) -> None:
    profile = _profile_with_score(tenant_id, 5.0)
    profile.acknowledge(tenant_id, NOW)
    assert RiskEscalationPolicy.should_escalate(profile, NormalizedRiskScore(8.0)) is False


def test_should_escalate_false_when_no_composite_score(tenant_id: TenantId) -> None:
    profile = RiskProfileFactory.create(
        tenant_id=tenant_id,
        subject_reference="asset-1",
        initial_contribution=_contribution(tenant_id),
        now=NOW,
    )
    profile.acknowledge(tenant_id, NOW)
    assert RiskEscalationPolicy.should_escalate(profile, NormalizedRiskScore(1.0)) is False


# --- RiskAcceptanceExpiryPolicy ---


def test_is_expired_true_after_expiry(tenant_id: TenantId) -> None:
    profile = _profile_with_score(tenant_id, 5.0)
    expires_at = NOW + timedelta(days=30)
    assert (
        RiskAcceptanceExpiryPolicy.is_expired(
            profile, NOW, expires_at, expires_at + timedelta(seconds=1)
        )
        is True
    )


def test_is_expired_false_before_expiry(tenant_id: TenantId) -> None:
    profile = _profile_with_score(tenant_id, 5.0)
    expires_at = NOW + timedelta(days=30)
    assert RiskAcceptanceExpiryPolicy.is_expired(profile, NOW, expires_at, NOW) is False


def test_escalation_precedence_documented() -> None:
    """The documented tie-break: escalation wins over acceptance
    expiry. Verified structurally by checking the module docstring of
    both policy modules (behavioral precedence is a caller-side
    responsibility, not enforced by either policy alone)."""
    import risk_engine.domain.policies.risk_acceptance_expiry_policy as expiry_module
    import risk_engine.domain.policies.risk_escalation_policy as escalation_module

    assert escalation_module.__doc__ is not None
    assert "escalation wins" in escalation_module.__doc__
    assert expiry_module.__doc__ is not None
    assert "escalation wins" in expiry_module.__doc__


# --- Specifications ---


def test_is_critical_risk_specification(tenant_id: TenantId) -> None:
    profile = _profile_with_score(tenant_id, 9.0)
    spec = IsCriticalRiskSpecification(threshold=NormalizedRiskScore(8.0))
    assert spec.is_satisfied_by(profile) is True
    spec_high = IsCriticalRiskSpecification(threshold=NormalizedRiskScore(9.5))
    assert spec_high.is_satisfied_by(profile) is False


def test_is_stale_risk_profile_specification(tenant_id: TenantId) -> None:
    profile = _profile_with_score(tenant_id, 5.0)
    spec = IsStaleRiskProfileSpecification(max_age=timedelta(days=1))
    assert spec.is_satisfied_by(profile, NOW + timedelta(hours=1)) is False
    assert spec.is_satisfied_by(profile, NOW + timedelta(days=2)) is True


def test_is_correlatable_signal_specification_consistent_with_service(tenant_id: TenantId) -> None:
    a = _signal(tenant_id)
    b = _signal(tenant_id, observed_at=NOW + timedelta(minutes=5))
    spec = IsCorrelatableSignalSpecification(window=timedelta(minutes=10))
    assert spec.is_satisfied_by(a, b) is True
    spec_narrow = IsCorrelatableSignalSpecification(window=timedelta(minutes=1))
    assert spec_narrow.is_satisfied_by(a, b) is False
