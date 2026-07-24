"""EventTimestamp — source-reported vs. platform-receipt time, kept
distinct per M37 §2.1 so detection/correlation windows can reason about
ingestion lag.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from siem_shared.domain.exceptions.domain_exceptions import (
    InvalidTimestampOrderingError,
    NaiveTimestampError,
)


@dataclass(frozen=True, slots=True)
class EventTimestamp:
    occurred_at: datetime
    ingested_at: datetime

    def __post_init__(self) -> None:
        if self.occurred_at.tzinfo is None:
            raise NaiveTimestampError("occurred_at")
        if self.ingested_at.tzinfo is None:
            raise NaiveTimestampError("ingested_at")
        if self.ingested_at < self.occurred_at:
            raise InvalidTimestampOrderingError()

    @property
    def ingestion_lag(self) -> timedelta:
        return self.ingested_at - self.occurred_at
