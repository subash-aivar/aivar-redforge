"""Timeline helpers."""

from __future__ import annotations

from incident.domain.aggregates.incident import Incident
from incident.domain.entities.timeline_entry import IncidentTimelineEntry


class IncidentTimelineService:
    def ordered_entries(self, incident: Incident) -> list[IncidentTimelineEntry]:
        return sorted(incident.timeline, key=lambda e: e.occurred_at)
