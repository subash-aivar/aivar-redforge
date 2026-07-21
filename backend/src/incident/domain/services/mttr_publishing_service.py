"""Publish classified/closed events to analytics incident_events."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from incident.domain.events.incident_events import IncidentClassified, IncidentClosed


class IAnalyticsIncidentEventPort(Protocol):
    async def publish_classified(self, event: IncidentClassified) -> None: ...

    async def publish_closed(self, event: IncidentClosed) -> None: ...


class MTTRPublishingService:
    def __init__(self, port: IAnalyticsIncidentEventPort) -> None:
        self._port = port

    async def publish_from_events(self, events: list[Any]) -> None:
        from incident.domain.events.incident_events import IncidentClassified, IncidentClosed

        for event in events:
            if isinstance(event, IncidentClassified):
                await self._port.publish_classified(event)
            elif isinstance(event, IncidentClosed):
                await self._port.publish_closed(event)
