"""Structlog-backed domain event publisher for execution context."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from execution.application.ports.i_unit_of_work import IEventPublisher

if TYPE_CHECKING:
    from execution.domain.events.base import BaseDomainEvent


class StructlogEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self._logger = structlog.get_logger("execution.events")

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        for event in events:
            try:
                self._logger.info(
                    "domain_event_published",
                    event_type=type(event).__name__,
                    event_id=event.event_id,
                    occurred_at=event.occurred_at.isoformat(),
                    aggregate_id=event.aggregate_id,
                    aggregate_type=event.aggregate_type,
                    tenant_id=str(event.tenant_id),
                )
            except Exception as exc:
                self._logger.warning("domain_event_publish_failed", error=str(exc))
