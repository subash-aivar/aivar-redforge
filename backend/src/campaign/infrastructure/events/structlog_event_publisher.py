"""StructlogEventPublisher — logs campaign domain events without raising."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from campaign.application.ports.i_event_publisher import IEventPublisher

if TYPE_CHECKING:
    from campaign.domain.events.base import BaseDomainEvent


class StructlogEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self._logger = structlog.get_logger("campaign.events")

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        try:
            for event in events:
                self._logger.info(
                    "domain_event_published",
                    event_type=type(event).__name__,
                    occurred_at=event.occurred_at.isoformat(),
                    aggregate_id=event.aggregate_id,
                    aggregate_type=event.aggregate_type,
                )
        except Exception as exc:
            self._logger.warning("domain_event_publish_failed", error=str(exc))
