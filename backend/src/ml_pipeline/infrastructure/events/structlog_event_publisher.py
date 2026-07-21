from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from ml_pipeline.domain.events.base import BaseDomainEvent

logger = structlog.get_logger(__name__)


class StructlogEventPublisher:
    def __init__(self) -> None:
        self.published: list[BaseDomainEvent] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        for event in events:
            self.published.append(event)
            logger.info(
                "ml_pipeline.domain_event",
                event_type=type(event).__name__,
                event_id=event.event_id,
                tenant_id=event.tenant_id,
            )
