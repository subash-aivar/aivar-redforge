from __future__ import annotations

from datetime import UTC, datetime

import pytest

from siem_analytics.domain.exceptions.domain_exceptions import NegativeMetricValueError
from siem_analytics.domain.value_objects.enums import MetricCategory
from siem_analytics.domain.value_objects.metric_sample import MetricSample

NOW = datetime.now(UTC)


def test_metric_sample_construction() -> None:
    sample = MetricSample(
        tenant_id="t-1",
        category=MetricCategory.INGESTION_VOLUME,
        value=1234.0,
        observed_at=NOW,
    )
    assert sample.value == 1234.0


def test_metric_sample_zero_value_is_allowed() -> None:
    sample = MetricSample(
        tenant_id="t-1", category=MetricCategory.ALERT_QUEUE_DEPTH, value=0.0, observed_at=NOW
    )
    assert sample.value == 0.0


def test_metric_sample_rejects_negative_value() -> None:
    with pytest.raises(NegativeMetricValueError):
        MetricSample(
            tenant_id="t-1",
            category=MetricCategory.DETECTION_RATE,
            value=-1.0,
            observed_at=NOW,
        )
