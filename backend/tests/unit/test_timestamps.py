"""Unit tests for AuditTimestamps and utc_now."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from redforge.shared.timestamps import AuditTimestamps, utc_now


def test_utc_now_returns_aware_datetime() -> None:
    now = utc_now()
    assert now.tzinfo is not None
    assert now.tzinfo == UTC


def test_create_sets_both_timestamps_to_now() -> None:
    before = datetime.now(UTC)
    timestamps = AuditTimestamps.create()
    after = datetime.now(UTC)

    assert before <= timestamps.created_at <= after
    assert timestamps.created_at == timestamps.updated_at


def test_mark_updated_preserves_created_at() -> None:
    fixed_time = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
    timestamps = AuditTimestamps(created_at=fixed_time, updated_at=fixed_time)

    later_time = fixed_time + timedelta(hours=1)
    with patch("redforge.shared.timestamps.utc_now", return_value=later_time):
        updated = timestamps.mark_updated()

    assert updated.created_at == fixed_time
    assert updated.updated_at == later_time


def test_mark_updated_returns_new_instance() -> None:
    timestamps = AuditTimestamps.create()

    with patch(
        "redforge.shared.timestamps.utc_now",
        return_value=datetime(2030, 1, 1, tzinfo=UTC),
    ):
        updated = timestamps.mark_updated()

    assert updated is not timestamps
    assert timestamps.updated_at != updated.updated_at


def test_immutable() -> None:
    timestamps = AuditTimestamps.create()
    with pytest.raises(AttributeError):
        timestamps.created_at = datetime.now(UTC)  # type: ignore[misc]
