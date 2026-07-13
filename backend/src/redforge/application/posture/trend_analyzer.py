"""Pure trend computation over a sequence of ValidationSnapshots.

TrendAnalyzer is a stateless domain service: given an ordered list of
snapshots (oldest first) and a TrendPolicy, it returns a ValidationTrend.
No I/O, no side effects.
"""

from __future__ import annotations

import math

from redforge.domain.posture.exceptions import InsufficientHistoryError
from redforge.domain.posture.value_objects import (
    TrendDirection,
    TrendPolicy,
    ValidationTrend,
    ValidationWindow,
)

if __name__ == "__main__":
    pass

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.domain.posture.entity import ValidationSnapshot


class TrendAnalyzer:
    """Stateless service: compute ValidationTrend from an ordered snapshot list.

    Usage:
        analyzer = TrendAnalyzer(policy)
        trend = analyzer.compute(snapshots, window)
    """

    def __init__(self, policy: TrendPolicy | None = None) -> None:
        self._policy = policy or TrendPolicy()

    def compute(
        self,
        snapshots: list[ValidationSnapshot],
        window: ValidationWindow,
    ) -> ValidationTrend:
        """Return a ValidationTrend for the given snapshots.

        Raises InsufficientHistoryError if fewer than policy.min_snapshots_for_trend
        snapshots are provided.
        """
        n = len(snapshots)
        if n < self._policy.min_snapshots_for_trend:
            target_id = snapshots[0].target_id if snapshots else "unknown"
            raise InsufficientHistoryError(
                target_id=target_id,
                required=self._policy.min_snapshots_for_trend,
                available=n,
            )

        rates = [s.vulnerability_rate for s in snapshots]
        first_rate = rates[0]
        last_rate = rates[-1]
        delta = last_rate - first_rate
        std_dev = _std_dev(rates)

        direction = self._classify(delta, std_dev)

        return ValidationTrend(
            direction=direction,
            first_rate=first_rate,
            last_rate=last_rate,
            delta=delta,
            snapshot_count=n,
            std_dev=std_dev,
            window=window,
        )

    def _classify(self, delta: float, std_dev: float) -> TrendDirection:
        if std_dev > self._policy.volatility_threshold:
            return TrendDirection.VOLATILE
        if delta <= -self._policy.improvement_threshold:
            return TrendDirection.IMPROVING
        if delta >= self._policy.degradation_threshold:
            return TrendDirection.DEGRADING
        return TrendDirection.STABLE


def _std_dev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)
