"""Immutable detection-result DTOs (M44A §8).

Read-once outcomes returned synchronously to the caller — never
persisted. The Detection Engine's responsibility ends at producing
these; it never creates an `Alert`, never correlates, never opens an
investigation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from siem_detection.application.dtos.detection_match import DetectionMatch


class DetectionStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    RULE_SKIPPED = "rule_skipped"
    RULE_DISABLED = "rule_disabled"
    EVALUATION_REJECTED = "evaluation_rejected"
    PARTIALLY_SUCCEEDED = "partially_succeeded"


@dataclass(frozen=True, slots=True)
class DetectionFailure:
    stage: str
    error_type: str
    message: str


@dataclass(frozen=True, slots=True)
class RuleEvaluationOutcome:
    """One rule's outcome for one event."""

    rule_id: str
    status: DetectionStatus
    match: DetectionMatch | None = None
    failures: tuple[DetectionFailure, ...] = ()

    def __post_init__(self) -> None:
        if self.match is not None and self.status != DetectionStatus.SUCCEEDED:
            raise ValueError(
                f"Only a SUCCEEDED RuleEvaluationOutcome may carry a match, got {self.status}"
            )


@dataclass(frozen=True, slots=True)
class EventDetectionResult:
    """One event's outcomes across every active rule it was evaluated
    against."""

    status: DetectionStatus
    event_id: str
    outcomes: tuple[RuleEvaluationOutcome, ...] = ()
    failures: tuple[DetectionFailure, ...] = ()

    def __post_init__(self) -> None:
        if self.status == DetectionStatus.EVALUATION_REJECTED:
            if not self.failures:
                raise ValueError("EVALUATION_REJECTED EventDetectionResult must carry failures")
            if self.outcomes:
                raise ValueError("EVALUATION_REJECTED EventDetectionResult must carry no outcomes")

    @property
    def matches(self) -> tuple[DetectionMatch, ...]:
        return tuple(o.match for o in self.outcomes if o.match is not None)


@dataclass(frozen=True, slots=True)
class BatchDetectionResult:
    status: DetectionStatus
    results: tuple[EventDetectionResult, ...] = field(default_factory=tuple)

    @property
    def succeeded_count(self) -> int:
        return sum(1 for r in self.results if r.status == DetectionStatus.SUCCEEDED)

    @property
    def failed_count(self) -> int:
        return len(self.results) - self.succeeded_count

    @property
    def matches(self) -> tuple[DetectionMatch, ...]:
        return tuple(match for r in self.results for match in r.matches)
