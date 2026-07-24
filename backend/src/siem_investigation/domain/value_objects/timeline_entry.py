"""A single ordered entry in an `InvestigationTimeline` (M37 §7)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    event_id: str
    occurred_at: datetime
    category: str
    summary: str

    def __post_init__(self) -> None:
        if not self.event_id.strip():
            raise ValueError("TimelineEntry.event_id must be a non-empty string")
        if not self.summary.strip():
            raise ValueError("TimelineEntry.summary must be a non-empty string")
