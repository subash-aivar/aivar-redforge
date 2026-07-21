"""IncidentTimelineEntry — append-only child entity."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from incident.domain.value_objects.enums import TimelineEntryType


@dataclass(frozen=True, slots=True)
class IncidentTimelineEntry:
    entry_id: UUID
    entry_type: TimelineEntryType
    summary: str
    actor: str
    occurred_at: datetime
    details: dict[str, str]

    @classmethod
    def create(
        cls,
        entry_type: TimelineEntryType,
        summary: str,
        actor: str,
        occurred_at: datetime,
        details: dict[str, str] | None = None,
    ) -> IncidentTimelineEntry:
        return cls(uuid4(), entry_type, summary, actor, occurred_at, dict(details or {}))
