"""StructlogEventPublisher — logs domain events without raising,
mirroring `threat_actor_intel.infrastructure.events.
structlog_event_publisher` exactly (the platform-wide convention for a
context's local `IEventPublisher`).

Honest limitation: this is best-effort structured logging only — not
a durable event bus, not a transactional outbox. A publish failure is
swallowed (logged as a warning) rather than raised, so it can never
undo an already-committed transaction, but it also means an event can
be silently dropped if the log sink itself is unavailable at publish
time. A transactional-outbox integration (the platform already has one
precedent, in the `automated_action` bounded context) is explicitly
deferred — not implemented here, and not claimed to be."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from ioc_intelligence.application.ports.i_event_publisher import IEventPublisher

if TYPE_CHECKING:
    from ioc_intelligence.domain.events.base import BaseDomainEvent


class StructlogEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self._logger = structlog.get_logger("ioc_intelligence.events")

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
