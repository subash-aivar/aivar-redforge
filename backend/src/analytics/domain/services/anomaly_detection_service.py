"""Anomaly detection — Z-score, IQR, IQR_ROLLING (Phase 1+5); ML via external score."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from analytics.domain.value_objects.enums import AnomalySeverity, DetectionMethod

if TYPE_CHECKING:
    from analytics.domain.aggregates.anomaly_detection_baseline import (
        AnomalyDetectionBaseline,
    )


@dataclass(frozen=True, slots=True)
class AnomalyResult:
    is_anomaly: bool
    score: float
    severity: AnomalySeverity
    method: DetectionMethod
    bootstrapped: bool


class AnomalyDetectionService:
    ZSCORE_WARNING = 2.0
    ZSCORE_CRITICAL = 3.0
    IQR_WARNING_K = 1.5
    IQR_CRITICAL_K = 3.0
    # Tighter fences for bursty signals (Phase 5 IQR_ROLLING)
    IQR_ROLLING_WARNING_K = 1.0
    IQR_ROLLING_CRITICAL_K = 2.0
    ML_WARNING = 3.0
    ML_CRITICAL = 6.0

    def evaluate(self, baseline: AnomalyDetectionBaseline, observed: float) -> AnomalyResult:
        if baseline.method == DetectionMethod.ML_ISOLATION_FOREST:
            # Caller must use evaluate_from_ml_score — cold path returns not-anomaly
            return AnomalyResult(
                False, 0.0, AnomalySeverity.INFO, DetectionMethod.ML_ISOLATION_FOREST, False
            )
        if not baseline.bootstrapped:
            return AnomalyResult(False, 0.0, AnomalySeverity.INFO, baseline.method, False)
        if baseline.method == DetectionMethod.ZSCORE:
            return self._zscore(baseline, observed)
        if baseline.method == DetectionMethod.IQR_ROLLING:
            return self._iqr(
                baseline,
                observed,
                warning_k=self.IQR_ROLLING_WARNING_K,
                critical_k=self.IQR_ROLLING_CRITICAL_K,
                method=DetectionMethod.IQR_ROLLING,
            )
        return self._iqr(
            baseline,
            observed,
            warning_k=self.IQR_WARNING_K,
            critical_k=self.IQR_CRITICAL_K,
            method=DetectionMethod.IQR,
        )

    def evaluate_from_ml_score(self, *, anomaly_score: float, available: bool) -> AnomalyResult:
        if not available:
            return AnomalyResult(
                False,
                0.0,
                AnomalySeverity.INFO,
                DetectionMethod.ML_ISOLATION_FOREST,
                False,
            )
        if anomaly_score >= self.ML_CRITICAL:
            return AnomalyResult(
                True,
                anomaly_score,
                AnomalySeverity.CRITICAL,
                DetectionMethod.ML_ISOLATION_FOREST,
                True,
            )
        if anomaly_score >= self.ML_WARNING:
            return AnomalyResult(
                True,
                anomaly_score,
                AnomalySeverity.WARNING,
                DetectionMethod.ML_ISOLATION_FOREST,
                True,
            )
        return AnomalyResult(
            False,
            anomaly_score,
            AnomalySeverity.INFO,
            DetectionMethod.ML_ISOLATION_FOREST,
            True,
        )

    def _zscore(self, baseline: AnomalyDetectionBaseline, observed: float) -> AnomalyResult:
        if baseline.std_dev == 0.0:
            score = 0.0 if observed == baseline.mean else float("inf")
        else:
            score = abs(observed - baseline.mean) / baseline.std_dev
        if score >= self.ZSCORE_CRITICAL:
            return AnomalyResult(
                True, score, AnomalySeverity.CRITICAL, DetectionMethod.ZSCORE, True
            )
        if score >= self.ZSCORE_WARNING:
            return AnomalyResult(True, score, AnomalySeverity.WARNING, DetectionMethod.ZSCORE, True)
        return AnomalyResult(False, score, AnomalySeverity.INFO, DetectionMethod.ZSCORE, True)

    def _iqr(
        self,
        baseline: AnomalyDetectionBaseline,
        observed: float,
        *,
        warning_k: float,
        critical_k: float,
        method: DetectionMethod,
    ) -> AnomalyResult:
        iqr = baseline.q3 - baseline.q1
        if iqr == 0.0:
            score = 0.0 if baseline.q1 <= observed <= baseline.q3 else float("inf")
            if score == 0.0:
                return AnomalyResult(False, score, AnomalySeverity.INFO, method, True)
            return AnomalyResult(True, score, AnomalySeverity.CRITICAL, method, True)
        lower_w = baseline.q1 - warning_k * iqr
        upper_w = baseline.q3 + warning_k * iqr
        lower_c = baseline.q1 - critical_k * iqr
        upper_c = baseline.q3 + critical_k * iqr
        if observed < lower_c or observed > upper_c:
            score = abs(observed - baseline.mean) / iqr
            return AnomalyResult(True, score, AnomalySeverity.CRITICAL, method, True)
        if observed < lower_w or observed > upper_w:
            score = abs(observed - baseline.mean) / iqr
            return AnomalyResult(True, score, AnomalySeverity.WARNING, method, True)
        return AnomalyResult(False, 0.0, AnomalySeverity.INFO, method, True)
