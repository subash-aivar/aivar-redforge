"""CorrelationPublisher — emits correlation lifecycle domain events."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import uuid7

from detection.domain.events.correlation_events import (
    FindingCorrelationCompleted,
    FindingCorrelationFailed,
    FindingCorrelationStarted,
)

if TYPE_CHECKING:
    from detection.application.ports.i_event_publisher import IEventPublisher
    from detection.domain.value_objects.identifiers import TenantId


class CorrelationPublisher:
    def __init__(self, event_publisher: IEventPublisher) -> None:
        self._publisher = event_publisher

    async def started(self, *, tenant_id: TenantId, finding_id: str) -> None:
        now = datetime.now(UTC)
        await self._publisher.publish_batch(
            [
                FindingCorrelationStarted(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=tenant_id,
                    aggregate_id=finding_id,
                    aggregate_type="DetectionFinding",
                    finding_id=finding_id,
                )
            ]
        )

    async def completed(
        self,
        *,
        tenant_id: TenantId,
        finding_id: str,
        status: str,
        sources_succeeded: int,
        sources_failed: int,
    ) -> None:
        now = datetime.now(UTC)
        await self._publisher.publish_batch(
            [
                FindingCorrelationCompleted(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=tenant_id,
                    aggregate_id=finding_id,
                    aggregate_type="DetectionFinding",
                    finding_id=finding_id,
                    status=status,
                    sources_succeeded=sources_succeeded,
                    sources_failed=sources_failed,
                )
            ]
        )

    async def failed(
        self, *, tenant_id: TenantId, finding_id: str, reason: str
    ) -> None:
        now = datetime.now(UTC)
        await self._publisher.publish_batch(
            [
                FindingCorrelationFailed(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=tenant_id,
                    aggregate_id=finding_id,
                    aggregate_type="DetectionFinding",
                    finding_id=finding_id,
                    reason=reason[:2048],
                )
            ]
        )
