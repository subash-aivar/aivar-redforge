"""ReplayEngine — all 8 filter dimensions required by Sprint 24.

The replay engine wraps InMemoryEventStore's iter_* helpers and adds:
- Replay by organisation
- Replay by stream (campaign, asset, validation)
- Replay by aggregate (type + id)
- Replay by time range
- Replay by correlation ID
- Replay by event type
- Replay from cursor (paginated)
- Replay by aggregate type (all streams for a given type)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence
    from datetime import datetime

from redforge.application.platform.event_store import InMemoryEventStore
from redforge.domain.platform.events import EventEnvelope
from redforge.domain.platform.value_objects import ReplayCursor


class ReplayEngine:
    """All 8 replay filter dimensions against an InMemoryEventStore."""

    def __init__(self, store: InMemoryEventStore) -> None:
        self._store = store

    async def replay_organization(
        self,
        organization_id: str,
        from_position: int = 0,
        max_events: int | None = None,
    ) -> AsyncIterator[EventEnvelope]:
        async for ev in self._store.iter_org(organization_id, from_position, max_events):
            yield ev

    async def replay_stream(
        self,
        stream_id: str,
        organization_id: str,
        from_stream_position: int = 0,
    ) -> AsyncIterator[EventEnvelope]:
        async for ev in self._store.iter_stream(stream_id, organization_id, from_stream_position):
            yield ev

    async def replay_aggregate(
        self,
        aggregate_type: str,
        aggregate_id: str,
        organization_id: str,
        from_position: int = 0,
    ) -> AsyncIterator[EventEnvelope]:
        async for ev in self._store.iter_aggregate(
            aggregate_type, aggregate_id, organization_id, from_position
        ):
            yield ev

    async def replay_by_time_range(
        self,
        organization_id: str,
        from_dt: datetime,
        to_dt: datetime,
        event_types: Sequence[str] | None = None,
    ) -> AsyncIterator[EventEnvelope]:
        async for ev in self._store.iter_by_time_range(
            organization_id, from_dt, to_dt, event_types
        ):
            yield ev

    async def replay_by_correlation_id(
        self,
        correlation_id: str,
        organization_id: str,
    ) -> AsyncIterator[EventEnvelope]:
        async for ev in self._store.iter_by_correlation(correlation_id, organization_id):
            yield ev

    async def replay_by_event_type(
        self,
        event_type: str,
        organization_id: str,
        from_position: int = 0,
        max_events: int | None = None,
    ) -> AsyncIterator[EventEnvelope]:
        async for ev in self._store.iter_by_event_type(
            event_type, organization_id, from_position, max_events
        ):
            yield ev

    async def replay_from_cursor(
        self,
        cursor: ReplayCursor,
        organization_id: str,
        max_events: int | None = None,
    ) -> tuple[list[EventEnvelope], ReplayCursor]:
        return await self._store.iter_from_cursor(cursor, organization_id, max_events)

    async def replay_aggregate_type(
        self,
        aggregate_type: str,
        organization_id: str,
        from_position: int = 0,
    ) -> AsyncIterator[EventEnvelope]:
        """Replay all events for a given aggregate type (e.g. all Campaigns)."""
        async for ev in self._store.iter_org(organization_id, from_position):
            if ev.aggregate_type == aggregate_type:
                yield ev

    async def collect(
        self,
        iterator: AsyncIterator[EventEnvelope],
    ) -> list[EventEnvelope]:
        """Convenience: collect an async iterator into a list."""
        results: list[EventEnvelope] = []
        async for ev in iterator:
            results.append(ev)
        return results
