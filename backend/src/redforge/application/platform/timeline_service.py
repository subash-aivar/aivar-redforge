"""TimelineService — builds Timeline and AuditTimeline views.

Assembles ordered TimelineEntry views from EventEnvelopes.
Knowledge Graph is NOT included here — KG projection is in projections/kg_projection.py.
"""

from __future__ import annotations

from typing import Any

from redforge.application.platform.event_store import InMemoryEventStore
from redforge.domain.platform.events import EventEnvelope
from redforge.domain.platform.read_models import AuditTimeline, Timeline
from redforge.domain.platform.value_objects import TimelineEntry


def _summarise(envelope: EventEnvelope) -> str:
    """Produce a human-readable summary line for a timeline entry."""
    return f"{envelope.event_type} on {envelope.aggregate_type}:{envelope.aggregate_id}"


def _details(envelope: EventEnvelope) -> dict[str, Any]:
    return {
        "stream_id": envelope.stream_id,
        "stream_position": envelope.stream_position,
        "correlation_id": envelope.correlation_id,
        "causation_id": envelope.causation_id,
        "actor_id": envelope.metadata.actor_id,
        "source_service": envelope.metadata.source_service,
    }


class TimelineService:
    """Assembles Timeline and AuditTimeline objects from EventEnvelopes."""

    def __init__(self, store: InMemoryEventStore) -> None:
        self._store = store

    async def get_timeline(
        self,
        subject_type: str,
        subject_id: str,
        organization_id: str,
        from_position: int = 0,
        max_entries: int | None = None,
    ) -> Timeline:
        envelopes = await self._load_subject_events(
            subject_type, subject_id, organization_id, from_position, max_entries
        )
        entries = tuple(
            TimelineEntry(
                event_id=ev.event_id,
                event_type=ev.event_type,
                aggregate_type=ev.aggregate_type,
                aggregate_id=ev.aggregate_id,
                occurred_at=ev.occurred_at,
                recorded_at=ev.recorded_at,
                organization_id=ev.organization_id,
                correlation_id=ev.correlation_id,
                summary=_summarise(ev),
                details=_details(ev),
                global_position=ev.global_position,
            )
            for ev in envelopes
        )
        from_pos = entries[0].global_position if entries else 0
        to_pos = entries[-1].global_position if entries else 0
        return Timeline(
            subject_type=subject_type,
            subject_id=subject_id,
            organization_id=organization_id,
            entries=entries,
            total_events=len(entries),
            from_position=from_pos,
            to_position=to_pos,
        )

    async def get_audit_timeline(
        self,
        subject_type: str,
        subject_id: str,
        organization_id: str,
        from_position: int = 0,
        max_entries: int | None = None,
    ) -> AuditTimeline:
        envelopes = await self._load_subject_events(
            subject_type, subject_id, organization_id, from_position, max_entries
        )
        entries = tuple(
            TimelineEntry(
                event_id=ev.event_id,
                event_type=ev.event_type,
                aggregate_type=ev.aggregate_type,
                aggregate_id=ev.aggregate_id,
                occurred_at=ev.occurred_at,
                recorded_at=ev.recorded_at,
                organization_id=ev.organization_id,
                correlation_id=ev.correlation_id,
                summary=_summarise(ev),
                details=_details(ev),
                global_position=ev.global_position,
            )
            for ev in envelopes
        )
        actor_summary: dict[str, int] = {}
        for ev in envelopes:
            actor = ev.metadata.actor_id or "system"
            actor_summary[actor] = actor_summary.get(actor, 0) + 1

        from_pos = entries[0].global_position if entries else 0
        to_pos = entries[-1].global_position if entries else 0
        return AuditTimeline(
            subject_type=subject_type,
            subject_id=subject_id,
            organization_id=organization_id,
            entries=entries,
            total_events=len(entries),
            from_position=from_pos,
            to_position=to_pos,
            actor_summary=actor_summary,
        )

    async def _load_subject_events(
        self,
        subject_type: str,
        subject_id: str,
        organization_id: str,
        from_position: int,
        max_entries: int | None,
    ) -> list[EventEnvelope]:
        stream_id = f"{subject_type}:{subject_id}"
        try:
            events = await self._store.read_stream(
                stream_id=stream_id,
                organization_id=organization_id,
                from_position=from_position,
                max_count=max_entries,
            )
            return list(events)
        except Exception:
            # Stream doesn't exist — return empty
            return []
