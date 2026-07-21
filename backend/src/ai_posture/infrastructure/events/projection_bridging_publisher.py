"""Event publisher that updates Phase 5 projections after domain publish."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_posture.application.ports.i_event_publisher import IEventPublisher
from ai_posture.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ai_posture.application.projections.projection_service import M31ProjectionService
    from ai_posture.domain.events.base import BaseDomainEvent


class ProjectionBridgingPublisher(IEventPublisher):
    def __init__(
        self,
        projections: M31ProjectionService,
        inner: IEventPublisher | None = None,
    ) -> None:
        self._projections = projections
        self._inner = inner or StructlogEventPublisher()

    async def publish_batch(self, events: Sequence[BaseDomainEvent]) -> None:
        batch = list(events)
        await self._inner.publish_batch(batch)
        for event in batch:
            await self._projections.apply(event)
