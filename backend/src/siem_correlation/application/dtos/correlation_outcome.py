"""Immutable correlation-outcome DTOs (M44B §8).

Read-once outcomes returned synchronously to the caller — never
persisted. The Correlation Engine's responsibility ends at producing
these; it never creates an `Alert`, never opens an investigation, never
scores risk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from siem_correlation.application.dtos.correlation_result import CorrelationResult


class CorrelationStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SESSION_EXPIRED = "session_expired"
    SESSION_CLOSED = "session_closed"
    DUPLICATE_EVENT = "duplicate_event"
    SESSION_AT_CAPACITY = "session_at_capacity"
    UNSUPPORTED_EVALUATOR = "unsupported_evaluator"
    EVALUATION_REJECTED = "evaluation_rejected"
    PARTIALLY_SUCCEEDED = "partially_succeeded"


@dataclass(frozen=True, slots=True)
class CorrelationFailure:
    stage: str
    error_type: str
    message: str


@dataclass(frozen=True, slots=True)
class CorrelationOutcome:
    """One `CorrelationInput`'s outcome."""

    correlation_rule_id: str
    status: CorrelationStatus
    result: CorrelationResult | None = None
    failures: tuple[CorrelationFailure, ...] = ()

    def __post_init__(self) -> None:
        if self.result is not None and self.status != CorrelationStatus.SUCCEEDED:
            raise ValueError(
                f"Only a SUCCEEDED CorrelationOutcome may carry a result, got {self.status}"
            )


@dataclass(frozen=True, slots=True)
class BatchCorrelationResult:
    status: CorrelationStatus
    outcomes: tuple[CorrelationOutcome, ...] = field(default_factory=tuple)

    @property
    def succeeded_count(self) -> int:
        return sum(1 for o in self.outcomes if o.status == CorrelationStatus.SUCCEEDED)

    @property
    def failed_count(self) -> int:
        return len(self.outcomes) - self.succeeded_count

    @property
    def matches(self) -> tuple[CorrelationResult, ...]:
        return tuple(o.result for o in self.outcomes if o.result is not None)
