from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from exposure.application.ports.i_event_publisher import IEventPublisher

if TYPE_CHECKING:
    from exposure.domain.events.base import BaseDomainEvent

log = structlog.get_logger(__name__)


class StructlogEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.published: list[BaseDomainEvent] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        for event in events:
            self.published.append(event)
            log.info(
                "exposure.domain_event",
                event_type=type(event).__name__,
                event_id=event.event_id,
                aggregate_id=event.aggregate_id,
            )
