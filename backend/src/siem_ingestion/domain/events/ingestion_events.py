"""Domain events produced by siem_ingestion (M37 §2.4)."""

from __future__ import annotations

from dataclasses import dataclass

from siem_ingestion.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class EventBatchIngested(BaseDomainEvent):
    batch_fingerprint: str = ""
    source_vendor: str = ""
    event_count: int = 0


@dataclass(frozen=True, slots=True)
class EventBatchThrottled(BaseDomainEvent):
    batch_fingerprint: str = ""
    source_vendor: str = ""
    event_count: int = 0
    throttle_reason: str = ""
