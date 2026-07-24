"""DiscoveryWindow — the time span a discovery run scans over (M45A),
structurally analogous to a `TimeRange` but named for this context's
own ubiquitous language rather than imported from `siem_*`."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from cloud_security.domain.exceptions.domain_exceptions import InvalidDiscoveryWindowError


@dataclass(frozen=True, slots=True)
class DiscoveryWindow:
    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.end <= self.start:
            raise InvalidDiscoveryWindowError()

    @property
    def duration(self) -> timedelta:
        return self.end - self.start
