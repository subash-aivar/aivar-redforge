from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from ai_agent_governance.application.ports.i_event_publisher import IEventPublisher

if TYPE_CHECKING:
    from ai_agent_governance.domain.events.base import BaseDomainEvent

logger = structlog.get_logger(__name__)


class StructlogEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.published: list[BaseDomainEvent] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.published.extend(events)
        for event in events:
            logger.info("domain_event", event_type=type(event).__name__)
