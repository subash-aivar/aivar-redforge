"""AnalyticsMetric / AnalyticsSeries / AnalyticsResult — the Analytics
Engine's read-only result shapes (M44F §5). None of these types is
ever written anywhere; all are read-once, immutable projections of
whatever `IAnalyticsProvider` returned.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass(frozen=True, slots=True)
class AnalyticsMetric:
    group_key: Mapping[str, str]
    value: float
    sample_count: int

    def __post_init__(self) -> None:
        if self.sample_count < 0:
            raise ValueError(f"AnalyticsMetric.sample_count must be >= 0, got {self.sample_count}")


@dataclass(frozen=True, slots=True)
class AnalyticsSeries:
    group_key: Mapping[str, str]
    points: tuple[AnalyticsMetric, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class AnalyticsResult:
    entity_type: str
    aggregation_type: str
    metrics: tuple[AnalyticsMetric, ...] = field(default_factory=tuple)
    total_sample_count: int = 0

    def __post_init__(self) -> None:
        if self.total_sample_count < 0:
            raise ValueError(
                f"AnalyticsResult.total_sample_count must be >= 0, got {self.total_sample_count}"
            )
        summed = sum(m.sample_count for m in self.metrics)
        if summed > self.total_sample_count:
            raise ValueError(
                "AnalyticsResult.total_sample_count cannot be smaller than the sum of "
                "its metrics' sample_count"
            )
