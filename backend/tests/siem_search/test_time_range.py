from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from siem_search.domain.exceptions.domain_exceptions import InvalidTimeRangeError
from siem_search.domain.value_objects.time_range import TimeRange

NOW = datetime.now(UTC)


def test_time_range_duration() -> None:
    tr = TimeRange(start=NOW, end=NOW + timedelta(hours=24))
    assert tr.duration == timedelta(hours=24)


def test_time_range_rejects_end_before_start() -> None:
    with pytest.raises(InvalidTimeRangeError):
        TimeRange(start=NOW, end=NOW - timedelta(seconds=1))


def test_time_range_rejects_end_equal_start() -> None:
    with pytest.raises(InvalidTimeRangeError):
        TimeRange(start=NOW, end=NOW)


def test_contains_instant_within_range() -> None:
    tr = TimeRange(start=NOW, end=NOW + timedelta(hours=1))
    assert tr.contains(NOW + timedelta(minutes=30)) is True


def test_contains_instant_at_end_boundary_excluded() -> None:
    end = NOW + timedelta(hours=1)
    tr = TimeRange(start=NOW, end=end)
    assert tr.contains(end) is False


def test_contains_instant_before_start_excluded() -> None:
    tr = TimeRange(start=NOW, end=NOW + timedelta(hours=1))
    assert tr.contains(NOW - timedelta(seconds=1)) is False
