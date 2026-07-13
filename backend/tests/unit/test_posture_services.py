"""Unit tests for posture application services.

Covers:
  - TrendAnalyzer: direction classification, std dev, insufficient history
  - RegressionAnalyzer: severity classification, noise floor, improvement detection
  - DriftDetector: no drift, single drift, multi drift, fingerprint-based
  - SecurityPostureCalculator: empty, single snapshot, multi-target
"""

from __future__ import annotations

import pytest

from redforge.application.posture.drift_detector import DriftDetector
from redforge.application.posture.posture_calculator import SecurityPostureCalculator
from redforge.application.posture.regression_analyzer import RegressionAnalyzer
from redforge.application.posture.trend_analyzer import TrendAnalyzer
from redforge.domain.posture.entity import ValidationBaseline, ValidationSnapshot
from redforge.domain.posture.exceptions import InsufficientHistoryError
from redforge.domain.posture.value_objects import (
    BaselinePolicy,
    ConfigurationFingerprint,
    DriftType,
    PostureLevel,
    RegressionSeverity,
    SnapshotMetrics,
    TrendDirection,
    TrendPolicy,
    ValidationWindow,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _metrics(
    vuln_rate: float = 0.10,
    total: int = 20,
    findings: int = 2,
) -> SnapshotMetrics:
    return SnapshotMetrics(
        vulnerability_rate=vuln_rate,
        total_attacks=total,
        finding_count=findings,
        duration_ms=3000,
        pass_rate=1.0 - vuln_rate,
    )


def _fp(
    model: str = "gpt-4o",
    provider: str = "openai",
    prompt_hash: str = "aaaa",
    categories: frozenset[str] | None = None,
) -> ConfigurationFingerprint:
    return ConfigurationFingerprint(
        model=model,
        provider=provider,
        system_prompt_hash=prompt_hash,
        attack_categories=categories or frozenset({"pi"}),
        tool_names=("search",),
    )


def _snap(
    target_id: str = "target-1",
    org_id: str = "org-1",
    vuln_rate: float = 0.10,
    fp: ConfigurationFingerprint | None = None,
) -> ValidationSnapshot:
    snap, _ = ValidationSnapshot.create(
        organization_id=org_id,
        target_id=target_id,
        run_id="run-x",
        metrics=_metrics(vuln_rate),
        fingerprint=fp or _fp(),
    )
    return snap


def _baseline_for(
    snapshot: ValidationSnapshot,
) -> ValidationBaseline:
    bl, _ = ValidationBaseline.establish(
        organization_id=snapshot.organization_id,
        target_id=snapshot.target_id,
        snapshot=snapshot,
        policy=BaselinePolicy(),
    )
    return bl


# ─── TrendAnalyzer ────────────────────────────────────────────────────────────


class TestTrendAnalyzer:
    def test_improving_trend(self) -> None:
        snaps = [
            _snap(vuln_rate=r)
            for r in [0.30, 0.25, 0.20, 0.15, 0.10]
        ]
        analyzer = TrendAnalyzer()
        trend = analyzer.compute(snaps, ValidationWindow.last_30_days())
        assert trend.direction == TrendDirection.IMPROVING
        assert trend.is_improving
        assert trend.delta < 0

    def test_degrading_trend(self) -> None:
        snaps = [
            _snap(vuln_rate=r)
            for r in [0.10, 0.15, 0.20, 0.25, 0.30]
        ]
        trend = TrendAnalyzer().compute(snaps, ValidationWindow.last_30_days())
        assert trend.direction == TrendDirection.DEGRADING
        assert trend.is_degrading

    def test_stable_trend(self) -> None:
        snaps = [_snap(vuln_rate=0.15) for _ in range(5)]
        trend = TrendAnalyzer().compute(snaps, ValidationWindow.last_30_days())
        assert trend.direction == TrendDirection.STABLE

    def test_volatile_trend(self) -> None:
        snaps = [
            _snap(vuln_rate=r)
            for r in [0.05, 0.90, 0.05, 0.90, 0.05]
        ]
        policy = TrendPolicy(volatility_threshold=0.15)
        trend = TrendAnalyzer(policy).compute(snaps, ValidationWindow.last_30_days())
        assert trend.direction == TrendDirection.VOLATILE

    def test_raises_insufficient_history(self) -> None:
        snaps = [_snap()]
        with pytest.raises(InsufficientHistoryError):
            TrendAnalyzer().compute(snaps, ValidationWindow.last_30_days())

    def test_trend_snapshot_count(self) -> None:
        snaps = [_snap(vuln_rate=0.2) for _ in range(7)]
        trend = TrendAnalyzer().compute(snaps, ValidationWindow.last_30_days())
        assert trend.snapshot_count == 7

    def test_trend_std_dev_zero_for_stable(self) -> None:
        snaps = [_snap(vuln_rate=0.10) for _ in range(4)]
        trend = TrendAnalyzer().compute(snaps, ValidationWindow.last_30_days())
        assert trend.std_dev == pytest.approx(0.0)

    def test_custom_policy_thresholds(self) -> None:
        snaps = [_snap(vuln_rate=r) for r in [0.10, 0.12]]
        # delta is 0.02, below 0.05 degradation threshold → STABLE
        trend = TrendAnalyzer(TrendPolicy(degradation_threshold=0.05)).compute(
            snaps, ValidationWindow.last_30_days()
        )
        assert trend.direction == TrendDirection.STABLE

    def test_just_meets_min_snapshots(self) -> None:
        snaps = [_snap(vuln_rate=0.1), _snap(vuln_rate=0.2)]
        trend = TrendAnalyzer().compute(snaps, ValidationWindow.last_30_days())
        assert trend.snapshot_count == 2


# ─── RegressionAnalyzer ───────────────────────────────────────────────────────


class TestRegressionAnalyzer:
    def test_no_result_for_noise_floor(self) -> None:
        snap = _snap(vuln_rate=0.10)
        base_snap = _snap(vuln_rate=0.10005)  # < 0.001 delta
        baseline = _baseline_for(base_snap)
        result = RegressionAnalyzer().analyze(snap, baseline)
        assert result is None

    def test_regression_detected(self) -> None:
        current = _snap(vuln_rate=0.30)
        base = _snap(vuln_rate=0.10)
        baseline = _baseline_for(base)
        result = RegressionAnalyzer().analyze(current, baseline)
        assert result is not None
        assert result.is_regression
        assert result.vulnerability_rate_delta == pytest.approx(0.20)

    def test_improvement_detected(self) -> None:
        current = _snap(vuln_rate=0.05)
        base = _snap(vuln_rate=0.30)
        baseline = _baseline_for(base)
        result = RegressionAnalyzer().analyze(current, baseline)
        assert result is not None
        assert result.is_improvement
        assert result.vulnerability_rate_delta < 0

    @pytest.mark.parametrize("delta, expected_severity", [
        (0.25, RegressionSeverity.CRITICAL),
        (0.12, RegressionSeverity.HIGH),
        (0.07, RegressionSeverity.MEDIUM),
        (0.02, RegressionSeverity.LOW),
        (0.005, RegressionSeverity.INFORMATIONAL),
    ])
    def test_severity_classification(
        self, delta: float, expected_severity: RegressionSeverity
    ) -> None:
        current = _snap(vuln_rate=0.10 + delta)
        base = _snap(vuln_rate=0.10)
        baseline = _baseline_for(base)
        result = RegressionAnalyzer().analyze(current, baseline)
        assert result is not None
        assert result.severity == expected_severity

    def test_description_is_nonempty(self) -> None:
        current = _snap(vuln_rate=0.30)
        base = _snap(vuln_rate=0.10)
        baseline = _baseline_for(base)
        result = RegressionAnalyzer().analyze(current, baseline)
        assert result is not None
        assert len(result.description) > 0


# ─── DriftDetector ────────────────────────────────────────────────────────────


class TestDriftDetector:
    def test_no_drift_returns_none(self) -> None:
        s1 = _snap(fp=_fp())
        s2 = _snap(fp=_fp())
        result = DriftDetector().detect(s1, s2)
        assert result is None

    def test_model_drift_detected(self) -> None:
        s1 = _snap(fp=_fp(model="gpt-4o"))
        s2 = _snap(fp=_fp(model="gpt-4-turbo"))
        result = DriftDetector().detect(s1, s2)
        assert result is not None
        assert DriftType.MODEL in result.drift_types
        assert result.has_model_drift

    def test_prompt_drift_detected(self) -> None:
        s1 = _snap(fp=_fp(prompt_hash="aaa"))
        s2 = _snap(fp=_fp(prompt_hash="bbb"))
        result = DriftDetector().detect(s1, s2)
        assert result is not None
        assert result.has_prompt_drift

    def test_multi_drift(self) -> None:
        s1 = _snap(fp=_fp(model="gpt-4o", provider="openai"))
        s2 = _snap(fp=_fp(model="claude-3", provider="anthropic"))
        result = DriftDetector().detect(s1, s2)
        assert result is not None
        assert DriftType.MODEL in result.drift_types
        assert DriftType.PROVIDER in result.drift_types

    def test_drift_is_significant_for_model_change(self) -> None:
        s1 = _snap(fp=_fp(model="gpt-4o"))
        s2 = _snap(fp=_fp(model="claude-3"))
        result = DriftDetector().detect(s1, s2)
        assert result is not None
        assert result.is_significant

    def test_detect_from_baseline_fingerprint(self) -> None:
        base_fp = _fp(model="gpt-4o")
        current = _snap(fp=_fp(model="claude-3"))
        result = DriftDetector().detect_from_baseline(
            baseline_snapshot_id="baseline-snap-001",
            baseline_fingerprint=base_fp,
            current=current,
        )
        assert result is not None
        assert DriftType.MODEL in result.drift_types

    def test_detect_from_baseline_non_fingerprint_returns_none(self) -> None:
        current = _snap()
        result = DriftDetector().detect_from_baseline(
            baseline_snapshot_id="x",
            baseline_fingerprint="not-a-fingerprint",
            current=current,
        )
        assert result is None


# ─── SecurityPostureCalculator ────────────────────────────────────────────────


class TestSecurityPostureCalculator:
    def test_empty_snapshots(self) -> None:
        calc = SecurityPostureCalculator()
        score = calc.calculate([], ValidationWindow.last_30_days())
        assert score.targets_assessed == 0
        assert score.mean_vulnerability_rate == 0.0
        assert score.level == PostureLevel.EXCELLENT
        assert score.trend == TrendDirection.NEW

    def test_single_snapshot(self) -> None:
        snaps = [_snap(vuln_rate=0.10)]
        score = SecurityPostureCalculator().calculate(snaps, ValidationWindow.last_30_days())
        assert score.targets_assessed == 1
        assert score.mean_vulnerability_rate == pytest.approx(0.10)
        assert score.level == PostureLevel.GOOD

    def test_multi_target_aggregation(self) -> None:
        snaps = [
            _snap(target_id="t1", vuln_rate=0.10),
            _snap(target_id="t2", vuln_rate=0.60),
        ]
        score = SecurityPostureCalculator().calculate(snaps, ValidationWindow.last_30_days())
        assert score.targets_assessed == 2
        assert score.mean_vulnerability_rate == pytest.approx(0.35)

    def test_critical_target_counted(self) -> None:
        snaps = [
            _snap(target_id="critical-target", vuln_rate=0.90),
            _snap(target_id="ok-target", vuln_rate=0.05),
        ]
        score = SecurityPostureCalculator().calculate(snaps, ValidationWindow.last_30_days())
        assert score.critical_targets == 1
        assert score.has_critical_targets

    def test_total_findings_summed(self) -> None:
        # _metrics default: finding_count=2
        snaps = [_snap() for _ in range(3)]
        score = SecurityPostureCalculator().calculate(snaps, ValidationWindow.last_30_days())
        assert score.total_findings == 6

    def test_posture_level_poor_for_high_rate(self) -> None:
        snaps = [_snap(vuln_rate=0.45)]
        score = SecurityPostureCalculator().calculate(snaps, ValidationWindow.last_30_days())
        assert score.level == PostureLevel.POOR

    def test_trend_direction_improving(self) -> None:
        # Use a gentler slope so std_dev stays below volatility threshold
        snaps = [
            _snap(target_id="t1", vuln_rate=r)
            for r in [0.20, 0.18, 0.16, 0.14, 0.12]
        ]
        score = SecurityPostureCalculator().calculate(snaps, ValidationWindow.last_30_days())
        assert score.trend == TrendDirection.IMPROVING
