"""Domain events produced by siem_correlation (M37 §2.4)."""

from __future__ import annotations

from dataclasses import dataclass, field

from siem_correlation.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class CorrelationSessionOpened(BaseDomainEvent):
    rule_id: str = ""
    window_expires_at: str = ""


@dataclass(frozen=True, slots=True)
class CorrelationMatched(BaseDomainEvent):
    rule_id: str = ""
    correlated_event_ids: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class CorrelationSessionExpired(BaseDomainEvent):
    rule_id: str = ""
    accumulated_event_count: int = 0
