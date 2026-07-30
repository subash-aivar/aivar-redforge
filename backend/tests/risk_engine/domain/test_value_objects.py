from __future__ import annotations

import math
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from types import MappingProxyType

import pytest

from risk_engine.domain.exceptions.domain_exceptions import (
    InvalidNormalizedRiskScoreError,
    InvalidRiskSignalReferenceError,
    InvalidRiskWeightProfileError,
)
from risk_engine.domain.value_objects.composite_score import CompositeRiskScore
from risk_engine.domain.value_objects.enums import RiskDimension, RiskScale, RiskSignalType
from risk_engine.domain.value_objects.identifiers import TenantId
from risk_engine.domain.value_objects.normalized_score import NormalizedRiskScore
from risk_engine.domain.value_objects.risk_signal import RiskSignalReference
from risk_engine.domain.value_objects.weight_profile import RiskWeightProfile

NOW = datetime(2026, 1, 1, tzinfo=UTC)


# --- NormalizedRiskScore ---


def test_normalized_risk_score_valid() -> None:
    assert NormalizedRiskScore(5.0).value == 5.0
    NormalizedRiskScore(0.0)
    NormalizedRiskScore(10.0)


@pytest.mark.parametrize("value", [-0.1, 10.1, math.nan, math.inf, -math.inf])
def test_normalized_risk_score_invalid(value: float) -> None:
    with pytest.raises(InvalidNormalizedRiskScoreError):
        NormalizedRiskScore(value)


def test_normalized_risk_score_frozen() -> None:
    score = NormalizedRiskScore(5.0)
    with pytest.raises(FrozenInstanceError):
        score.value = 1.0  # type: ignore[misc]


# --- RiskSignalReference ---


def test_risk_signal_reference_valid(tenant_id: TenantId) -> None:
    ref = RiskSignalReference(
        tenant_id=tenant_id,
        source_context="vulnerability_engine",
        source_aggregate_type="AssetVulnerability",
        source_id="abc",
        signal_type=RiskSignalType.SEVERITY_RATING,
        raw_value=7.0,
        raw_scale=RiskScale.CVSS_0_10,
        observed_at=NOW,
    )
    assert ref.raw_value == 7.0


@pytest.mark.parametrize(
    "field_name,value",
    [("source_context", ""), ("source_aggregate_type", ""), ("source_id", "")],
)
def test_risk_signal_reference_rejects_empty_strings(
    tenant_id: TenantId, field_name: str, value: str
) -> None:
    kwargs = {
        "tenant_id": tenant_id,
        "source_context": "vulnerability_engine",
        "source_aggregate_type": "AssetVulnerability",
        "source_id": "abc",
        "signal_type": RiskSignalType.SEVERITY_RATING,
        "raw_value": 7.0,
        "raw_scale": RiskScale.CVSS_0_10,
        "observed_at": NOW,
    }
    kwargs[field_name] = value
    with pytest.raises(InvalidRiskSignalReferenceError):
        RiskSignalReference(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("raw_value", [math.nan, math.inf, -math.inf])
def test_risk_signal_reference_rejects_non_finite_raw_value(
    tenant_id: TenantId, raw_value: float
) -> None:
    with pytest.raises(InvalidRiskSignalReferenceError):
        RiskSignalReference(
            tenant_id=tenant_id,
            source_context="vulnerability_engine",
            source_aggregate_type="AssetVulnerability",
            source_id="abc",
            signal_type=RiskSignalType.SEVERITY_RATING,
            raw_value=raw_value,
            raw_scale=RiskScale.CVSS_0_10,
            observed_at=NOW,
        )


def test_risk_signal_reference_frozen(tenant_id: TenantId) -> None:
    ref = RiskSignalReference(
        tenant_id=tenant_id,
        source_context="c",
        source_aggregate_type="t",
        source_id="i",
        signal_type=RiskSignalType.SEVERITY_RATING,
        raw_value=1.0,
        raw_scale=RiskScale.CVSS_0_10,
        observed_at=NOW,
    )
    with pytest.raises(FrozenInstanceError):
        ref.raw_value = 2.0  # type: ignore[misc]


# --- RiskWeightProfile ---


def test_risk_weight_profile_valid() -> None:
    profile = RiskWeightProfile(
        profile_name="default",
        version=1,
        weights=MappingProxyType({RiskDimension.VULNERABILITY: 1.0}),
    )
    assert profile.weight_for(RiskDimension.VULNERABILITY) == 1.0
    assert profile.weight_for(RiskDimension.CLOUD) == 0.0
    assert isinstance(profile.weights, MappingProxyType)


def test_risk_weight_profile_accepts_plain_dict_and_wraps_it() -> None:
    profile = RiskWeightProfile(profile_name="default", version=1, weights={RiskDimension.AI: 2.0})
    assert isinstance(profile.weights, MappingProxyType)


def test_risk_weight_profile_rejects_negative_weight() -> None:
    with pytest.raises(InvalidRiskWeightProfileError):
        RiskWeightProfile(profile_name="p", version=1, weights={RiskDimension.AI: -1.0})


def test_risk_weight_profile_rejects_all_zero_weights() -> None:
    with pytest.raises(InvalidRiskWeightProfileError):
        RiskWeightProfile(profile_name="p", version=1, weights={RiskDimension.AI: 0.0})


def test_risk_weight_profile_rejects_empty_name() -> None:
    with pytest.raises(InvalidRiskWeightProfileError):
        RiskWeightProfile(profile_name=" ", version=1, weights={RiskDimension.AI: 1.0})


def test_risk_weight_profile_rejects_bad_version() -> None:
    with pytest.raises(InvalidRiskWeightProfileError):
        RiskWeightProfile(profile_name="p", version=0, weights={RiskDimension.AI: 1.0})


def test_risk_weight_profile_frozen() -> None:
    profile = RiskWeightProfile(profile_name="p", version=1, weights={RiskDimension.AI: 1.0})
    with pytest.raises(FrozenInstanceError):
        profile.version = 2  # type: ignore[misc]


# --- CompositeRiskScore ---


def test_composite_risk_score_valid() -> None:
    score = CompositeRiskScore(
        value=NormalizedRiskScore(5.0), weight_profile_id="default:v1", computed_at=NOW
    )
    assert score.value.value == 5.0


def test_composite_risk_score_rejects_empty_weight_profile_id() -> None:
    with pytest.raises(InvalidRiskWeightProfileError):
        CompositeRiskScore(value=NormalizedRiskScore(5.0), weight_profile_id="", computed_at=NOW)


def test_composite_risk_score_frozen() -> None:
    score = CompositeRiskScore(
        value=NormalizedRiskScore(5.0), weight_profile_id="default:v1", computed_at=NOW
    )
    with pytest.raises(FrozenInstanceError):
        score.weight_profile_id = "x"  # type: ignore[misc]
