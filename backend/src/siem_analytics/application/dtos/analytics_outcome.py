"""Immutable analytics-outcome DTOs (M44F §5).

Read-once outcomes returned synchronously to the caller — never
persisted. The Analytics Engine's responsibility ends at producing
these; it never builds dashboards, never computes risk scores, never
persists anything. Mirrors `siem_search.application.dtos.search_outcome`
(M44E).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from siem_analytics.application.dtos.analytics_metric import AnalyticsResult


class AnalyticsStatus(StrEnum):
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    UNSUPPORTED_PROVIDER = "unsupported_provider"
    FAILED = "failed"
    PARTIALLY_SUCCEEDED = "partially_succeeded"


@dataclass(frozen=True, slots=True)
class AnalyticsFailure:
    stage: str
    error_type: str
    message: str


@dataclass(frozen=True, slots=True)
class AnalyticsOutcome:
    status: AnalyticsStatus
    result: AnalyticsResult | None = None
    failures: tuple[AnalyticsFailure, ...] = ()

    def __post_init__(self) -> None:
        result_required = self.status == AnalyticsStatus.SUCCEEDED
        if result_required and self.result is None:
            raise ValueError(f"{self.status} AnalyticsOutcome must carry a result")
        if not result_required and self.result is not None:
            raise ValueError(f"{self.status} AnalyticsOutcome must not carry a result")


@dataclass(frozen=True, slots=True)
class BatchAnalyticsResult:
    status: AnalyticsStatus
    outcomes: tuple[AnalyticsOutcome, ...] = field(default_factory=tuple)

    @property
    def succeeded_count(self) -> int:
        return sum(1 for o in self.outcomes if o.status == AnalyticsStatus.SUCCEEDED)

    @property
    def failed_count(self) -> int:
        return len(self.outcomes) - self.succeeded_count
