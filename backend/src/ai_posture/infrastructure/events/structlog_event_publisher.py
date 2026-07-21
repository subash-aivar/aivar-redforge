from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ai_posture.application.ports.i_event_publisher import IEventPublisher

if TYPE_CHECKING:
    from ai_posture.domain.events.base import BaseDomainEvent

log = logging.getLogger(__name__)


class StructlogEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.published: list[BaseDomainEvent] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.published.extend(events)
        for event in events:
            log.info("ai_posture.event %s %s", type(event).__name__, event.aggregate_id)
