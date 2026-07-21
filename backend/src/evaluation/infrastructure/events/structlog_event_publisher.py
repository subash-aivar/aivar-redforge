"""Structlog-based event publisher for evaluation context."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from evaluation.application.ports.i_event_publisher import IEventPublisher

if TYPE_CHECKING:
    from evaluation.domain.events.base import BaseDomainEvent

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class StructlogEventPublisher(IEventPublisher):
    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        for event in events:
            log.info(
                "domain_event",
                event_type=type(event).__name__,
                event_id=event.event_id,
                aggregate_id=event.aggregate_id,
                aggregate_type=event.aggregate_type,
                tenant_id=str(event.tenant_id),
                occurred_at=event.occurred_at.isoformat(),
            )
