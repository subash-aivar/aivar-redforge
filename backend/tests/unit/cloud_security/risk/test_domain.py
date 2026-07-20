"""Domain unit tests for Cloud Risk Correlation Engine."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from redforge.domain.cloud_security.risk.engine import CloudRiskEngine, RiskSignalSnapshot
from redforge.domain.cloud_security.risk.exceptions import (
    InvalidRiskArgumentError,
    InvalidRiskTransitionError,
)
from redforge.domain.cloud_security.risk.factor import (
    CloudRiskAssessment,
    CloudRiskExposure,
    CloudRiskFactor,
)
from redforge.domain.cloud_security.risk.score import CloudRiskScore
from redforge.domain.cloud_security.risk.value_objects import (
    RiskCalculationVersion,
    RiskCategory,
    RiskConfidence,
    RiskDimensionScores,
    RiskScore,
    RiskSeverity,
    RiskSource,
    RiskState,
    RiskTrend,
    RiskWeightProfile,
    compute_weighted_overall,
    severity_to_score,
)
from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId

ORG = OrganizationId("01HXORG0000000000000000001")
ASSET = CloudAssetId(uuid4())
NOW = datetime(2026, 7, 19, 12, 0, 0, tzinfo=UTC)


def test_default_weights_sum_to_one() -> None:
    profile = RiskWeightProfile.default()
    assert abs(sum(profile.to_dict().values()) - 1.0) < 1e-9


def test_attack_path_weight_is_zero() -> None:
    assert RiskWeightProfile.default().attack_path == 0.0


@pytest.mark.parametrize(
    "weights",
    [
        {"threat_intel": 0.5, "compliance": 0.5, "identity": 0.1},
        {"threat_intel": 1.1},
        {"cspm": -0.1, "runtime": 1.1},
    ],
)
def test_invalid_weight_profiles_rejected(weights: dict[str, float]) -> None:
    with pytest.raises(ValueError):
        RiskWeightProfile.from_dict({**RiskWeightProfile.default().to_dict(), **weights})


def test_custom_valid_weights_accepted() -> None:
    profile = RiskWeightProfile(
        threat_intel=0.1,
        compliance=0.1,
        identity=0.1,
        exposure=0.1,
        attack_path=0.0,
        cspm=0.2,
        criticality=0.1,
        kubernetes=0.15,
        runtime=0.15,
    )
    assert abs(sum(profile.to_dict().values()) - 1.0) < 1e-9


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ("CRITICAL", 10.0),
        ("HIGH", 7.5),
        ("MEDIUM", 5.0),
        ("LOW", 2.5),
        ("INFO", 0.5),
        ("critical", 10.0),
        ("unknown", 0.0),
    ],
)
def test_severity_to_score(severity: str, expected: float) -> None:
    assert severity_to_score(severity) == expected


@pytest.mark.parametrize(
    ("value", "severity"),
    [
        (9.5, RiskSeverity.CRITICAL),
        (7.0, RiskSeverity.HIGH),
        (4.0, RiskSeverity.MEDIUM),
        (1.0, RiskSeverity.LOW),
        (0.0, RiskSeverity.INFO),
    ],
)
def test_risk_score_to_severity(value: float, severity: RiskSeverity) -> None:
    assert RiskScore.clamp(value).to_severity() == severity


def test_risk_score_rejects_out_of_range() -> None:
    with pytest.raises(ValueError):
        RiskScore(10.1)
    with pytest.raises(ValueError):
        RiskScore(-0.1)


def test_dimension_scores_reject_out_of_range() -> None:
    with pytest.raises(ValueError):
        RiskDimensionScores(cspm=11.0)


def test_engine_deterministic_for_same_snapshot(risky_snapshot: RiskSignalSnapshot) -> None:
    engine = CloudRiskEngine()
    d1, c1, e1 = engine.score_dimensions(risky_snapshot)
    d2, c2, e2 = engine.score_dimensions(risky_snapshot)
    assert d1.to_dict() == d2.to_dict()
    assert engine.overall(d1) == engine.overall(d2)
    assert len(c1) == len(c2)
    assert len(e1) == len(e2)


def test_engine_attack_path_always_zero(risky_snapshot: RiskSignalSnapshot) -> None:
    dims, _, _ = CloudRiskEngine().score_dimensions(risky_snapshot)
    assert dims.attack_path == 0.0


def test_engine_empty_snapshot_low_risk(empty_snapshot: RiskSignalSnapshot) -> None:
    dims, _, _ = CloudRiskEngine().score_dimensions(empty_snapshot)
    overall = CloudRiskEngine().overall(dims)
    assert overall < 3.0


def test_engine_cspm_aggregates_with_diminishing() -> None:
    snap = RiskSignalSnapshot(open_finding_severities=("CRITICAL", "CRITICAL", "HIGH"))
    dims, _, _ = CloudRiskEngine().score_dimensions(snap)
    assert dims.cspm == 10.0


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        ("NONE", 0.0),
        ("LOW", 2.0),
        ("MEDIUM", 5.0),
        ("HIGH", 7.5),
        ("ADMIN", 10.0),
        ("weird", 3.0),
    ],
)
def test_identity_score_mapping(level: str, expected: float) -> None:
    snap = RiskSignalSnapshot(privilege_level=level)
    dims, _, _ = CloudRiskEngine().score_dimensions(snap)
    assert dims.identity == expected


@pytest.mark.parametrize(
    ("k8s", "expected"),
    [(None, 0.0), (100.0, 0.0), (0.0, 10.0), (50.0, 5.0)],
)
def test_k8s_score_inversion(k8s: float | None, expected: float) -> None:
    snap = RiskSignalSnapshot(k8s_security_score=k8s)
    dims, _, _ = CloudRiskEngine().score_dimensions(snap)
    assert dims.kubernetes == expected


def test_runtime_score_uses_max_severity() -> None:
    snap = RiskSignalSnapshot(runtime_event_severities=("LOW", "HIGH", "INFO"))
    dims, _, _ = CloudRiskEngine().score_dimensions(snap)
    assert dims.runtime == 7.5


def test_weighted_overall_matches_manual() -> None:
    dims = RiskDimensionScores(cspm=10.0, identity=10.0)
    weights = RiskWeightProfile.default()
    expected = (
        dims.cspm * weights.cspm
        + dims.identity * weights.identity
    )
    assert compute_weighted_overall(dims, weights).value == pytest.approx(expected)


def test_score_calculate_lifecycle() -> None:
    engine = CloudRiskEngine()
    snap = RiskSignalSnapshot(open_finding_severities=("HIGH",), privilege_level="HIGH")
    dims, components, evidence = engine.score_dimensions(snap)
    score = CloudRiskScore.calculate(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        dimensions=dims,
        components=components,
        evidence=evidence,
        now=NOW,
    )
    assert score.state == RiskState.ACTIVE
    assert score.trend == RiskTrend.UNKNOWN
    assert len(score.history) == 1
    events = score.pop_events()
    assert any(type(e).__name__ == "RiskCalculated" for e in events)


def test_score_update_sets_trend() -> None:
    engine = CloudRiskEngine()
    low = RiskSignalSnapshot(open_finding_severities=("LOW",))
    high = RiskSignalSnapshot(open_finding_severities=("CRITICAL", "HIGH"))
    d1, c1, e1 = engine.score_dimensions(low)
    first = CloudRiskScore.calculate(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        dimensions=d1,
        components=c1,
        evidence=e1,
        now=NOW,
    )
    first.pop_events()
    d2, c2, e2 = engine.score_dimensions(high)
    second = CloudRiskScore.calculate(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        dimensions=d2,
        components=c2,
        evidence=e2,
        previous=first,
        now=NOW + timedelta(hours=1),
    )
    assert second.trend == RiskTrend.WORSENING
    assert second.row_version == first.row_version + 1


def test_suppress_and_reopen() -> None:
    engine = CloudRiskEngine()
    dims, components, evidence = engine.score_dimensions(RiskSignalSnapshot())
    score = CloudRiskScore.calculate(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        dimensions=dims,
        components=components,
        evidence=evidence,
        now=NOW,
    )
    score.pop_events()
    score.suppress(reason="accepted", suppressed_by="user-1", now=NOW)
    assert score.state == RiskState.SUPPRESSED
    with pytest.raises(InvalidRiskTransitionError):
        score.suppress(reason="again", suppressed_by="user-1", now=NOW)
    score.reopen(reason="fixed", now=NOW + timedelta(minutes=1))
    assert score.state == RiskState.REOPENED


def test_suppress_requires_reason() -> None:
    engine = CloudRiskEngine()
    dims, components, evidence = engine.score_dimensions(RiskSignalSnapshot())
    score = CloudRiskScore.calculate(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        dimensions=dims,
        components=components,
        evidence=evidence,
        now=NOW,
    )
    with pytest.raises(InvalidRiskArgumentError):
        score.suppress(reason="  ", suppressed_by="u", now=NOW)


def test_mark_expired() -> None:
    engine = CloudRiskEngine()
    dims, components, evidence = engine.score_dimensions(RiskSignalSnapshot())
    score = CloudRiskScore.calculate(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        dimensions=dims,
        components=components,
        evidence=evidence,
        now=NOW,
        validity=timedelta(hours=1),
    )
    score.pop_events()
    score.mark_expired(now=NOW + timedelta(hours=2))
    assert score.state == RiskState.EXPIRED


def test_threshold_event_emitted() -> None:
    engine = CloudRiskEngine()
    snap = RiskSignalSnapshot(
        open_finding_severities=("CRITICAL",),
        privilege_level="ADMIN",
        network_exposure="PUBLIC",
        public_accessibility=True,
        encryption_at_rest=False,
        compliance_gap_ratio=1.0,
        business_criticality="CRITICAL",
        threat_intel_score=10.0,
        runtime_event_severities=("CRITICAL",),
        k8s_security_score=0.0,
    )
    dims, components, evidence = engine.score_dimensions(snap)
    score = CloudRiskScore.calculate(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        dimensions=dims,
        components=components,
        evidence=evidence,
        now=NOW,
        threshold=1.0,
    )
    names = [type(e).__name__ for e in score.pop_events()]
    assert "RiskThresholdExceeded" in names


def test_exposure_derive_scoring() -> None:
    exp = CloudRiskExposure.derive(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        public_accessibility=True,
        internet_exposure=True,
        encryption_at_rest=False,
        privilege_level="ADMIN",
        now=NOW,
    )
    assert exp.exposure_score == 10.0


def test_exposure_derive_minimal() -> None:
    exp = CloudRiskExposure.derive(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        now=NOW,
    )
    assert exp.exposure_score == 0.0
    assert exp.privilege_level == "NONE"


def test_factor_create_requires_title() -> None:
    with pytest.raises(InvalidRiskArgumentError):
        CloudRiskFactor.create(
            organization_id=ORG,
            cloud_asset_id=ASSET,
            category=RiskCategory.CSPM if hasattr(RiskCategory, "CSPM") else RiskCategory.CONFIGURATION,
            source=RiskSource.CSPM,
            title=" ",
            score=5.0,
            now=NOW,
        )


def test_factor_create_sets_severity() -> None:
    factor = CloudRiskFactor.create(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        category=RiskCategory.CONFIGURATION,
        source=RiskSource.CSPM,
        title="Open S3",
        score=9.2,
        confidence=RiskConfidence.HIGH,
        now=NOW,
    )
    assert factor.severity == RiskSeverity.CRITICAL


def test_assessment_complete() -> None:
    assessment = CloudRiskAssessment.start(
        organization_id=ORG,
        scope="ORGANIZATION",
        target_id=str(ORG),
        calculation_version="1.0.0+default",
        now=NOW,
    )
    assert assessment.status == "RUNNING"
    assessment.complete(
        assets_evaluated=3,
        risks_created=2,
        risks_updated=1,
        diagnostics={"ok": True},
        now=NOW + timedelta(seconds=5),
    )
    assert assessment.status == "COMPLETED"
    assert assessment.assets_evaluated == 3
    assert assessment.completed_at is not None


def test_calculation_version_round_trip() -> None:
    v = RiskCalculationVersion(major=1, minor=2, patch=3, profile="strict")
    assert str(v) == "1.2.3+strict"
    assert RiskCalculationVersion.from_dict(v.to_dict()).major == 1


def test_history_capped_at_100() -> None:
    engine = CloudRiskEngine()
    dims, components, evidence = engine.score_dimensions(RiskSignalSnapshot())
    score = CloudRiskScore.calculate(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        dimensions=dims,
        components=components,
        evidence=evidence,
        now=NOW,
    )
    for i in range(105):
        score = CloudRiskScore.calculate(
            organization_id=ORG,
            cloud_asset_id=ASSET,
            dimensions=dims,
            components=components,
            evidence=evidence,
            previous=score,
            now=NOW + timedelta(minutes=i + 1),
        )
        score.pop_events()
    assert len(score.history) <= 100


@pytest.mark.parametrize("category", list(RiskCategory))
def test_all_risk_categories_are_strings(category: RiskCategory) -> None:
    assert isinstance(category.value, str)


@pytest.mark.parametrize("state", list(RiskState))
def test_all_risk_states(state: RiskState) -> None:
    assert state.value


@pytest.mark.parametrize("source", list(RiskSource))
def test_all_risk_sources(source: RiskSource) -> None:
    assert source.value


def test_as_risk_score_clamp() -> None:
    engine = CloudRiskEngine()
    dims, components, evidence = engine.score_dimensions(RiskSignalSnapshot())
    score = CloudRiskScore.calculate(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        dimensions=dims,
        components=components,
        evidence=evidence,
        now=NOW,
    )
    assert 0.0 <= score.as_risk_score().value <= 10.0


def test_reopen_from_expired() -> None:
    engine = CloudRiskEngine()
    dims, components, evidence = engine.score_dimensions(RiskSignalSnapshot())
    score = CloudRiskScore.calculate(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        dimensions=dims,
        components=components,
        evidence=evidence,
        now=NOW,
        validity=timedelta(seconds=1),
    )
    score.pop_events()
    score.mark_expired(now=NOW + timedelta(hours=1))
    score.reopen(now=NOW + timedelta(hours=2))
    assert score.state == RiskState.REOPENED


def test_reopen_invalid_from_active() -> None:
    engine = CloudRiskEngine()
    dims, components, evidence = engine.score_dimensions(RiskSignalSnapshot())
    score = CloudRiskScore.calculate(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        dimensions=dims,
        components=components,
        evidence=evidence,
        now=NOW,
    )
    with pytest.raises(InvalidRiskTransitionError):
        score.reopen(now=NOW)
