"""StructlogEventPublisher — logs domain events without raising,
mirroring `attack_pattern_intel.infrastructure.events.
structlog_event_publisher` exactly.

Honest limitation: best-effort structured logging only — not a
durable event bus, not a transactional outbox."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from intelligence_relationships.application.ports.i_event_publisher import IEventPublisher

if TYPE_CHECKING:
    from intelligence_relationships.domain.events.base import BaseDomainEvent


class StructlogEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self._logger = structlog.get_logger("intelligence_relationships.events")

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        try:
            for event in events:
                self._logger.info(
                    "domain_event_published",
                    event_type=type(event).__name__,
                    occurred_at=event.occurred_at.isoformat(),
                    aggregate_id=event.aggregate_id,
                    aggregate_type=event.aggregate_type,
                    tenant_id=event.tenant_id,
                )
        except Exception as exc:
            self._logger.warning("domain_event_publish_failed", error=str(exc))
