from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from analytics.domain.aggregates.anomaly_detection_baseline import (
    AnomalyDetectionBaseline,
)
from analytics.domain.services.anomaly_detection_service import AnomalyDetectionService
from analytics.domain.value_objects.enums import AnomalySignalType, DetectionMethod
from analytics.domain.value_objects.identifiers import (
    AnomalyDetectionBaselineId,
    TenantId,
)


def _baseline(
    method: DetectionMethod, values: list[float], *, bootstrapped: bool = True
) -> AnomalyDetectionBaseline:
    tenant = TenantId(uuid4())
    baseline = AnomalyDetectionBaseline.create(
        AnomalyDetectionBaselineId.generate(),
        tenant,
        AnomalySignalType.VULNERABILITY_INGEST_RATE,
        method,
        30,
        datetime.now(UTC),
    )
    if bootstrapped:
        baseline.bootstrap(tenant, values=values, at=datetime.now(UTC))
    return baseline


def test_zscore_not_bootstrapped() -> None:
    svc = AnomalyDetectionService()
    baseline = _baseline(DetectionMethod.ZSCORE, [], bootstrapped=False)
    result = svc.evaluate(baseline, 100.0)
    assert result.is_anomaly is False
    assert result.severity.value == "Info"


def test_zscore_detects_outlier() -> None:
    svc = AnomalyDetectionService()
    baseline = _baseline(DetectionMethod.ZSCORE, [10.0] * 30)
    result = svc.evaluate(baseline, 50.0)
    assert result.is_anomaly is True


def test_iqr_detects_outlier() -> None:
    svc = AnomalyDetectionService()
    baseline = _baseline(DetectionMethod.IQR, [float(v) for v in range(1, 31)])
    result = svc.evaluate(baseline, 100.0)
    assert result.is_anomaly is True
