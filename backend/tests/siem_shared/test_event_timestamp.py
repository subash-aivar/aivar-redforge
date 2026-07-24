from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from siem_shared.domain.exceptions.domain_exceptions import (
    InvalidTimestampOrderingError,
    NaiveTimestampError,
)
from siem_shared.domain.value_objects.event_timestamp import EventTimestamp

NOW = datetime.now(UTC)


def test_construction_and_lag() -> None:
    ts = EventTimestamp(occurred_at=NOW, ingested_at=NOW + timedelta(seconds=5))
    assert ts.ingestion_lag == timedelta(seconds=5)


def test_zero_lag_is_allowed() -> None:
    ts = EventTimestamp(occurred_at=NOW, ingested_at=NOW)
    assert ts.ingestion_lag == timedelta(0)


def test_ingested_before_occurred_raises() -> None:
    with pytest.raises(InvalidTimestampOrderingError):
        EventTimestamp(occurred_at=NOW, ingested_at=NOW - timedelta(seconds=1))


def test_naive_occurred_at_raises() -> None:
    with pytest.raises(NaiveTimestampError, match="occurred_at"):
        EventTimestamp(occurred_at=datetime.now(), ingested_at=NOW)


def test_naive_ingested_at_raises() -> None:
    with pytest.raises(NaiveTimestampError, match="ingested_at"):
        EventTimestamp(occurred_at=NOW, ingested_at=datetime.now())
