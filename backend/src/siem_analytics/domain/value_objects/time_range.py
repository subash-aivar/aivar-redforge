"""TimeRange — the value object every siem_analytics query is scoped
by (M44F §1), mirroring `siem_search.domain.value_objects.time_range`
(M37 §10). Kept as this context's own value object rather than an
import from `siem_search` — the domain layer must not reach into a
sibling `siem_*` context.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from siem_analytics.domain.exceptions.domain_exceptions import InvalidTimeRangeError


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
