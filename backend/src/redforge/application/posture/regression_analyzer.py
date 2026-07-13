"""Regression and improvement detection vs a ValidationBaseline.

RegressionAnalyzer is a stateless domain service: given a current
ValidationSnapshot and a ValidationBaseline, it returns a
ValidationRegressionDetail (or None if neither regression nor improvement).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.posture.value_objects import (
    RegressionSeverity,
    ValidationRegressionDetail,
)

if TYPE_CHECKING:
    from redforge.domain.posture.entity import ValidationBaseline, ValidationSnapshot

# Thresholds for RegressionSeverity classification (vulnerability rate increase)
_SEVERITY_THRESHOLDS: list[tuple[float, RegressionSeverity]] = [
    (0.20, RegressionSeverity.CRITICAL),
    (0.10, RegressionSeverity.HIGH),
    (0.05, RegressionSeverity.MEDIUM),
    (0.01, RegressionSeverity.LOW),
    (0.0, RegressionSeverity.INFORMATIONAL),
]

# Minimum delta (absolute) to report at all; below this is noise
_NOISE_FLOOR = 0.001


class RegressionAnalyzer:
    """Stateless service: compare current snapshot to a baseline.

    Usage:
        analyzer = RegressionAnalyzer()
        detail = analyzer.analyze(current_snapshot, baseline)
        if detail and detail.is_regression:
            ...
    """

    def analyze(
        self,
        current: ValidationSnapshot,
        baseline: ValidationBaseline,
    ) -> ValidationRegressionDetail | None:
        """Return a ValidationRegressionDetail if there is a meaningful delta.

        Returns None when the delta is within the noise floor.
        """
        delta = current.vulnerability_rate - baseline.vulnerability_rate
        if abs(delta) < _NOISE_FLOOR:
            return None

        new_findings = max(
            0,
            current.metrics.finding_count - baseline.snapshot_metrics.finding_count,
        )
        severity = _classify_severity(delta)
        direction = "regression" if delta > 0 else "improvement"
        description = (
            f"{direction.capitalize()} detected: vulnerability rate changed by "
            f"{delta:+.1%} vs baseline (snapshot {baseline.snapshot_id[:8]})"
        )
        return ValidationRegressionDetail(
            baseline_snapshot_id=baseline.snapshot_id,
            current_snapshot_id=current.id,
            vulnerability_rate_delta=delta,
            new_finding_count=new_findings,
            severity=severity,
            description=description,
        )


def _classify_severity(delta: float) -> RegressionSeverity:
    """Classify regression severity by the absolute vulnerability rate delta."""
    abs_delta = abs(delta)
    for threshold, severity in _SEVERITY_THRESHOLDS:
        if abs_delta >= threshold:
            return severity
    return RegressionSeverity.INFORMATIONAL
