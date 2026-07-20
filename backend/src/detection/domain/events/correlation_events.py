"""Domain events for correlation lifecycle."""

from __future__ import annotations

from dataclasses import dataclass

from detection.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingCorrelationStarted(BaseDomainEvent):
    finding_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingCorrelationCompleted(BaseDomainEvent):
    finding_id: str
    status: str
    sources_succeeded: int
    sources_failed: int


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingCorrelationFailed(BaseDomainEvent):
    finding_id: str
    reason: str
