from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from siem_analytics.domain.exceptions.domain_exceptions import InvalidTimeRangeError
from siem_analytics.domain.value_objects.time_range import TimeRange

NOW = datetime.now(UTC)


def test_end_must_be_after_start():
    with pytest.raises(InvalidTimeRangeError):
        TimeRange(start=NOW, end=NOW)

    with pytest.raises(InvalidTimeRangeError):
        TimeRange(start=NOW, end=NOW - timedelta(seconds=1))


def test_duration():
    tr = TimeRange(start=NOW - timedelta(hours=2), end=NOW)
    assert tr.duration == timedelta(hours=2)


def test_contains():
    tr = TimeRange(start=NOW - timedelta(hours=1), end=NOW)
    assert tr.contains(NOW - timedelta(minutes=30))
    assert not tr.contains(NOW)
    assert not tr.contains(NOW - timedelta(hours=2))
