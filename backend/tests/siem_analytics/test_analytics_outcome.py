from __future__ import annotations

import pytest

from siem_analytics.application.dtos.analytics_metric import AnalyticsResult
from siem_analytics.application.dtos.analytics_outcome import AnalyticsOutcome, AnalyticsStatus


def test_succeeded_outcome_requires_result():
    with pytest.raises(ValueError, match="must carry a result"):
        AnalyticsOutcome(status=AnalyticsStatus.SUCCEEDED, result=None)


def test_non_succeeded_outcome_must_not_carry_result():
    result = AnalyticsResult(entity_type="events", aggregation_type="count")
    with pytest.raises(ValueError, match="must not carry a result"):
        AnalyticsOutcome(status=AnalyticsStatus.FAILED, result=result)


def test_succeeded_outcome_with_result_is_valid():
    result = AnalyticsResult(entity_type="events", aggregation_type="count")
    outcome = AnalyticsOutcome(status=AnalyticsStatus.SUCCEEDED, result=result)
    assert outcome.result is result
