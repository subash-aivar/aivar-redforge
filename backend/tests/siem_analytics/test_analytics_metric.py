from __future__ import annotations

import dataclasses

import pytest

from siem_analytics.application.dtos.analytics_metric import AnalyticsMetric, AnalyticsResult


def test_metric_requires_non_negative_sample_count():
    with pytest.raises(ValueError, match="sample_count"):
        AnalyticsMetric(group_key={}, value=1.0, sample_count=-1)


def test_metric_is_frozen():
    metric = AnalyticsMetric(group_key={}, value=1.0, sample_count=1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        metric.value = 2.0  # type: ignore[misc]


def test_result_requires_non_negative_total_sample_count():
    with pytest.raises(ValueError, match="total_sample_count"):
        AnalyticsResult(entity_type="events", aggregation_type="count", total_sample_count=-1)


def test_result_total_sample_count_cannot_be_smaller_than_metrics_sum():
    metric = AnalyticsMetric(group_key={}, value=1.0, sample_count=5)
    with pytest.raises(ValueError, match="total_sample_count"):
        AnalyticsResult(
            entity_type="events",
            aggregation_type="count",
            metrics=(metric,),
            total_sample_count=1,
        )


def test_result_accepts_consistent_totals():
    metric = AnalyticsMetric(group_key={}, value=1.0, sample_count=5)
    result = AnalyticsResult(
        entity_type="events", aggregation_type="count", metrics=(metric,), total_sample_count=5
    )
    assert result.total_sample_count == 5


def test_result_is_frozen():
    result = AnalyticsResult(entity_type="events", aggregation_type="count")
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.entity_type = "alerts"  # type: ignore[misc]
