"""StructlogEventPublisher — logs domain events without raising,
mirroring `risk_engine.infrastructure.events.structlog_event_publisher`
exactly (the platform-wide convention for a context's local
`IEventPublisher`, per ADR-M51.1-04). Does NOT integrate the platform
`PlatformEventPublisher`/EventStore or the Knowledge Graph — both are
explicitly deferred (ADR-M51.1-04/-05/-06)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from threat_actor_intel.application.ports.i_event_publisher import IEventPublisher

if TYPE_CHECKING:
    from threat_actor_intel.domain.events.base import BaseDomainEvent


class StructlogEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self._logger = structlog.get_logger("threat_actor_intel.events")

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
