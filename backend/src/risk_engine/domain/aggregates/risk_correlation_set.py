"""RiskCorrelationSet — the second aggregate root of risk_engine
(M48B): a group of `RiskSignalReference`s that `RiskCorrelationService`
has determined refer to the same subject within a correlation window.
A correlation of a single signal isn't a correlation, so at least two
references are required; all references must share the requesting
tenant."""

from __future__ import annotations

from typing import TYPE_CHECKING

from risk_engine.domain.events.correlation_events import RiskCorrelationSetFormed
from risk_engine.domain.exceptions.domain_exceptions import InvalidCorrelationSetError

if TYPE_CHECKING:
    from datetime import datetime

    from risk_engine.domain.events.base import BaseDomainEvent
    from risk_engine.domain.value_objects.identifiers import CorrelationSetId, TenantId
    from risk_engine.domain.value_objects.risk_signal import RiskSignalReference


class RiskCorrelationSet:
    __slots__ = (
        "_pending_events",
        "correlation_set_id",
        "formed_at",
        "signal_references",
        "tenant_id",
    )

    def __init__(
        self,
        correlation_set_id: CorrelationSetId,
        tenant_id: TenantId,
        signal_references: tuple[RiskSignalReference, ...],
        formed_at: datetime,
    ) -> None:
        self.correlation_set_id = correlation_set_id
        self.tenant_id = tenant_id
        self.signal_references = signal_references
        self.formed_at = formed_at
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    @classmethod
    def create(
        cls,
        correlation_set_id: CorrelationSetId,
        tenant_id: TenantId,
        signal_references: tuple[RiskSignalReference, ...],
        now: datetime,
    ) -> RiskCorrelationSet:
        if len(signal_references) < 2:
            raise InvalidCorrelationSetError(
                "a RiskCorrelationSet requires at least two signal references"
            )
        if any(ref.tenant_id != tenant_id for ref in signal_references):
            raise InvalidCorrelationSetError(
                "all signal references in a RiskCorrelationSet must belong to the same tenant"
            )
        correlation_set = cls(
            correlation_set_id=correlation_set_id,
            tenant_id=tenant_id,
            signal_references=signal_references,
            formed_at=now,
        )
        correlation_set._emit(
            RiskCorrelationSetFormed(
                tenant_id=str(tenant_id),
                aggregate_id=str(correlation_set_id),
                aggregate_type="RiskCorrelationSet",
                occurred_at=now,
                signal_count=len(signal_references),
            )
        )
        return correlation_set
