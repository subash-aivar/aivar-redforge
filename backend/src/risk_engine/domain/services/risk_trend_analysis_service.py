"""RiskTrendAnalysisService — a read-oriented domain service that
derives a `RiskTrendDirection` from a history of `CompositeRiskScore`
snapshots. Stateless, pure, no I/O. See `risk_engine.domain.events.
trend_events` for why `RiskTrendDetected` is not appended to any
aggregate's pending-events list."""

from __future__ import annotations

from itertools import pairwise
from typing import TYPE_CHECKING

from risk_engine.domain.value_objects.enums import RiskTrendDirection

if TYPE_CHECKING:
    from collections.abc import Sequence

    from risk_engine.domain.value_objects.composite_score import CompositeRiskScore

_VOLATILITY_THRESHOLD = 2.0
_STABLE_THRESHOLD = 0.25


class RiskTrendAnalysisService:
    @staticmethod
    def analyze_trend(history: Sequence[CompositeRiskScore]) -> RiskTrendDirection:
        """Heuristic: split the history in half (older half vs. newer
        half, chronological order assumed), compare average scores.
        `STABLE` if the averages differ by less than
        `_STABLE_THRESHOLD`; otherwise `INCREASING`/`DECREASING` by
        sign of the delta. If any single consecutive step swings by
        more than `_VOLATILITY_THRESHOLD`, classify as `VOLATILE`
        instead — a simple, easily explainable rule rather than a
        full time-series model, which is intentionally out of scope
        for a domain-layer service."""
        if len(history) < 2:
            return RiskTrendDirection.STABLE

        values = [snapshot.value.value for snapshot in history]

        for previous, current in pairwise(values):
            if abs(current - previous) >= _VOLATILITY_THRESHOLD:
                return RiskTrendDirection.VOLATILE

        midpoint = len(values) // 2
        older_half = values[:midpoint] if midpoint > 0 else values[:1]
        newer_half = values[midpoint:]
        older_avg = sum(older_half) / len(older_half)
        newer_avg = sum(newer_half) / len(newer_half)
        delta = newer_avg - older_avg

        if abs(delta) < _STABLE_THRESHOLD:
            return RiskTrendDirection.STABLE
        return RiskTrendDirection.INCREASING if delta > 0 else RiskTrendDirection.DECREASING
