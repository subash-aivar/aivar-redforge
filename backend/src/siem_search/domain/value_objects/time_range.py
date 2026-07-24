"""TimeRange — the value object every siem_search query shape is scoped
by (M37 §10). Tier selection (which of hot/warm/cold a given range
touches) is an application-layer concern added in M42 Phase 10, once
`siem_storage`'s tier boundaries are queryable through a port — this
domain layer intentionally does not import `siem_storage` directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from siem_search.domain.exceptions.domain_exceptions import InvalidTimeRangeError


@dataclass(frozen=True, slots=True)
class TimeRange:
    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.end <= self.start:
            raise InvalidTimeRangeError()

    @property
    def duration(self) -> timedelta:
        return self.end - self.start

    def contains(self, instant: datetime) -> bool:
        return self.start <= instant < self.end
