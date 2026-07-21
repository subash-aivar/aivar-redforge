"""Structlog event publisher for exposure_reporting."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from exposure_reporting.application.ports.i_event_publisher import IEventPublisher

if TYPE_CHECKING:
    from exposure_reporting.domain.events.base import BaseDomainEvent

logger = structlog.get_logger(__name__)


class StructlogEventPublisher(IEventPublisher):
    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        for event in events:
            logger.info(
                "exposure_reporting.domain_event",
                event_type=type(event).__name__,
                event_id=event.event_id,
                tenant_id=event.tenant_id,
                aggregate_id=event.aggregate_id,
            )
