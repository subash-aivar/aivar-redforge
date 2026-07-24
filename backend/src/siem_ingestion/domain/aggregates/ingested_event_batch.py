"""IngestedEventBatch aggregate — a bounded, replay-safe unit of
admission (M37 §2.2). Batching, not a single event, is the
throughput-relevant unit of admission control (M37 §3).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from siem_ingestion.domain.events.ingestion_events import (
    EventBatchIngested,
    EventBatchThrottled,
)
from siem_ingestion.domain.exceptions.domain_exceptions import (
    EmptyBatchError,
    InvalidBatchFingerprintError,
    InvalidBatchTransition,
    TenantMismatch,
)
from siem_ingestion.domain.value_objects.enums import BatchStatus

if TYPE_CHECKING:
    from datetime import datetime

    from siem_ingestion.domain.events.base import BaseDomainEvent
    from siem_ingestion.domain.value_objects.identifiers import (
        IngestedEventBatchId,
        TenantId,
    )
    from siem_ingestion.domain.value_objects.source_ref import IngestionSourceRef


class IngestedEventBatch:
    __slots__ = (
        "_pending_events",
        "batch_fingerprint",
        "batch_id",
        "event_count",
        "received_at",
        "resolved_at",
        "source",
        "status",
        "tenant_id",
        "throttle_reason",
    )

    def __init__(
        self,
        batch_id: IngestedEventBatchId,
        tenant_id: TenantId,
        source: IngestionSourceRef,
        batch_fingerprint: str,
        event_count: int,
        status: BatchStatus,
        received_at: datetime,
        resolved_at: datetime | None = None,
        throttle_reason: str | None = None,
    ) -> None:
        self.batch_id = batch_id
        self.tenant_id = tenant_id
        self.source = source
        self.batch_fingerprint = batch_fingerprint
        self.event_count = event_count
        self.status = status
        self.received_at = received_at
        self.resolved_at = resolved_at
        self.throttle_reason = throttle_reason
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    @classmethod
    def receive(
        cls,
        batch_id: IngestedEventBatchId,
        tenant_id: TenantId,
        source: IngestionSourceRef,
        batch_fingerprint: str,
        event_count: int,
        now: datetime,
    ) -> IngestedEventBatch:
        """Construct a batch in `PENDING` status, awaiting an admission
        decision (`admit`/`throttle`/`reject`)."""
        if event_count <= 0:
            raise EmptyBatchError()
        if not batch_fingerprint.strip():
            raise InvalidBatchFingerprintError()
        return cls(
            batch_id=batch_id,
            tenant_id=tenant_id,
            source=source,
            batch_fingerprint=batch_fingerprint,
            event_count=event_count,
            status=BatchStatus.PENDING,
            received_at=now,
        )

    def admit(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status != BatchStatus.PENDING:
            raise InvalidBatchTransition(self.status.value, BatchStatus.ACCEPTED.value)
        self.status = BatchStatus.ACCEPTED
        self.resolved_at = now
        self._emit(
            EventBatchIngested(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.batch_id),
                aggregate_type="IngestedEventBatch",
                occurred_at=now,
                batch_fingerprint=self.batch_fingerprint,
                source_vendor=self.source.vendor,
                event_count=self.event_count,
            )
        )

    def throttle(self, tenant_id: TenantId, reason: str, now: datetime) -> None:
        """Mark the batch as throttled — a first-class, non-error outcome
        (M37 §3): the source must degrade gracefully, not the pipeline
        block or crash."""
        self._assert_tenant(tenant_id)
        if self.status != BatchStatus.PENDING:
            raise InvalidBatchTransition(self.status.value, BatchStatus.THROTTLED.value)
        if not reason.strip():
            raise ValueError("throttle reason must be a non-empty string")
        self.status = BatchStatus.THROTTLED
        self.resolved_at = now
        self.throttle_reason = reason.strip()
        self._emit(
            EventBatchThrottled(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.batch_id),
                aggregate_type="IngestedEventBatch",
                occurred_at=now,
                batch_fingerprint=self.batch_fingerprint,
                source_vendor=self.source.vendor,
                event_count=self.event_count,
                throttle_reason=self.throttle_reason,
            )
        )

    def reject(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status != BatchStatus.PENDING:
            raise InvalidBatchTransition(self.status.value, BatchStatus.REJECTED.value)
        self.status = BatchStatus.REJECTED
        self.resolved_at = now
