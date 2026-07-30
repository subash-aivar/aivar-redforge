from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from risk_engine.domain.entities.risk_contribution import RiskContribution
from risk_engine.domain.exceptions.domain_exceptions import (
    EmptyContributionsError,
    UnsupportedRiskScaleError,
)
from risk_engine.domain.services.risk_composition_service import RiskCompositionService
from risk_engine.domain.services.risk_correlation_service import RiskCorrelationService
from risk_engine.domain.services.risk_normalization_service import RiskNormalizationService
from risk_engine.domain.services.risk_trend_analysis_service import RiskTrendAnalysisService
from risk_engine.domain.value_objects.composite_score import CompositeRiskScore
from risk_engine.domain.value_objects.enums import (
    RiskDimension,
    RiskScale,
    RiskSignalType,
    RiskTrendDirection,
)
from risk_engine.domain.value_objects.identifiers import TenantId
from risk_engine.domain.value_objects.normalized_score import NormalizedRiskScore
from risk_engine.domain.value_objects.risk_signal import RiskSignalReference
from risk_engine.domain.value_objects.weight_profile import RiskWeightProfile

NOW = datetime(2026, 1, 1, tzinfo=UTC)


# --- RiskNormalizationService ---


def test_normalize_cvss_passthrough() -> None:
    assert RiskNormalizationService.normalize(6.5, RiskScale.CVSS_0_10).value == 6.5


def test_normalize_probability_scaled() -> None:
    assert RiskNormalizationService.normalize(0.5, RiskScale.PROBABILITY_0_1).value == 5.0


def test_normalize_percentage_scaled() -> None:
    assert RiskNormalizationService.normalize(80.0, RiskScale.PERCENTAGE_0_100).value == 8.0


def test_normalize_custom_weighted_requires_prenormalized_value() -> None:
    assert RiskNormalizationService.normalize(4.0, RiskScale.CUSTOM_WEIGHTED).value == 4.0


def test_normalize_custom_weighted_out_of_range_rejected() -> None:
    with pytest.raises(UnsupportedRiskScaleError):
        RiskNormalizationService.normalize(15.0, RiskScale.CUSTOM_WEIGHTED)


# --- RiskCorrelationService ---


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


def test_are_correlatable_same_subject_within_window(tenant_id: TenantId) -> None:
    a = _signal(tenant_id)
    b = _signal(tenant_id, observed_at=NOW + timedelta(minutes=5))
    assert RiskCorrelationService.are_correlatable(a, b, window=timedelta(minutes=10)) is True


def test_are_correlatable_outside_window(tenant_id: TenantId) -> None:
    a = _signal(tenant_id)
    b = _signal(tenant_id, observed_at=NOW + timedelta(hours=1))
    assert RiskCorrelationService.are_correlatable(a, b, window=timedelta(minutes=10)) is False


def test_are_correlatable_different_subject(tenant_id: TenantId) -> None:
    a = _signal(tenant_id, subject_reference="asset-1")
    b = _signal(tenant_id, subject_reference="asset-2")
    assert RiskCorrelationService.are_correlatable(a, b, window=timedelta(days=1)) is False


def test_are_correlatable_missing_subject_reference(tenant_id: TenantId) -> None:
    a = _signal(tenant_id, subject_reference=None)
    b = _signal(tenant_id)
    assert RiskCorrelationService.are_correlatable(a, b, window=timedelta(days=1)) is False


# --- RiskCompositionService ---


def _contribution(tenant_id: TenantId, dimension: RiskDimension, value: float) -> RiskContribution:
    return RiskContribution(
        dimension=dimension,
        normalized_score=NormalizedRiskScore(value),
        source_signal=_signal(tenant_id),
        computed_at=NOW,
    )


def test_compose_weighted_average_over_populated_dimensions(tenant_id: TenantId) -> None:
    weight_profile = RiskWeightProfile(
        profile_name="default",
        version=1,
        weights={RiskDimension.VULNERABILITY: 1.0, RiskDimension.CLOUD: 3.0, RiskDimension.AI: 2.0},
    )
    contributions = [
        _contribution(tenant_id, RiskDimension.VULNERABILITY, 10.0),
        _contribution(tenant_id, RiskDimension.CLOUD, 0.0),
    ]
    # only VULNERABILITY and CLOUD are populated; AI's weight is excluded entirely
    result = RiskCompositionService.compose(contributions, weight_profile)
    expected = (1.0 * 10.0 + 3.0 * 0.0) / (1.0 + 3.0)
    assert result.value.value == pytest.approx(expected)
    assert result.weight_profile_id == "default:v1"


def test_compose_empty_contributions_rejected() -> None:
    weight_profile = RiskWeightProfile(profile_name="p", version=1, weights={RiskDimension.AI: 1.0})
    with pytest.raises(EmptyContributionsError):
        RiskCompositionService.compose([], weight_profile)


def test_compose_ignores_dimensions_with_zero_weight_even_if_contributed(
    tenant_id: TenantId,
) -> None:
    weight_profile = RiskWeightProfile(
        profile_name="p",
        version=1,
        weights={RiskDimension.VULNERABILITY: 1.0, RiskDimension.CLOUD: 0.0},
    )
    contributions = [
        _contribution(tenant_id, RiskDimension.VULNERABILITY, 8.0),
        _contribution(tenant_id, RiskDimension.CLOUD, 10.0),
    ]
    result = RiskCompositionService.compose(contributions, weight_profile)
    assert result.value.value == pytest.approx(8.0)


# --- RiskTrendAnalysisService ---


def _score(value: float) -> CompositeRiskScore:
    return CompositeRiskScore(
        value=NormalizedRiskScore(value), weight_profile_id="default:v1", computed_at=NOW
    )


def test_trend_stable_with_single_snapshot() -> None:
    assert RiskTrendAnalysisService.analyze_trend([_score(5.0)]) == RiskTrendDirection.STABLE


def test_trend_increasing() -> None:
    history = [_score(2.0), _score(2.1), _score(4.0), _score(4.2)]
    assert RiskTrendAnalysisService.analyze_trend(history) == RiskTrendDirection.INCREASING


def test_trend_decreasing() -> None:
    history = [_score(6.0), _score(5.8), _score(4.5), _score(4.2)]
    assert RiskTrendAnalysisService.analyze_trend(history) == RiskTrendDirection.DECREASING


def test_trend_stable_when_deltas_small() -> None:
    history = [_score(5.0), _score(5.05), _score(5.1), _score(5.05)]
    assert RiskTrendAnalysisService.analyze_trend(history) == RiskTrendDirection.STABLE


def test_trend_volatile_on_large_single_step_swing() -> None:
    history = [_score(2.0), _score(9.0), _score(2.0)]
    assert RiskTrendAnalysisService.analyze_trend(history) == RiskTrendDirection.VOLATILE
