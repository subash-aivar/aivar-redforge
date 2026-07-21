"""Enforces phase transition policy helpers."""

from __future__ import annotations

from incident.domain.aggregates.incident import Incident
from incident.domain.value_objects.enums import IncidentPhase, ResolutionType


class IncidentLifecycleService:
    def can_close_without_eradication(self, resolution: ResolutionType) -> bool:
        return resolution in {ResolutionType.FALSE_POSITIVE, ResolutionType.DUPLICATE}

    def is_active(self, incident: Incident) -> bool:
        return incident.phase != IncidentPhase.CLOSED
