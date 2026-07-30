"""Domain events emitted by the `RiskCorrelationSet` aggregate
(M48B)."""

from __future__ import annotations

from dataclasses import dataclass

from risk_engine.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class RiskCorrelationSetFormed(BaseDomainEvent):
    signal_count: int = 0
