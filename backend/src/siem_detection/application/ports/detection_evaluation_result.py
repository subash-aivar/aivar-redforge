"""DetectionEvaluationResult — the raw output of one `IDetectionEvaluator`
run against one `CanonicalEvent`.

Deliberately not a `DetectionMatch` itself: the evaluator decides only
whether/how strongly the event matched its rule; `DetectionApplicationService`
is what turns a positive result into the application-facing `DetectionMatch`
DTO (rule id, event id, match time are context the evaluator doesn't
need to know about).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from siem_shared.domain.value_objects.event_severity import EventSeverity


@dataclass(frozen=True, slots=True)
class DetectionEvaluationResult:
    matched: bool
    severity: EventSeverity
    confidence: float
    reason: str

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"DetectionEvaluationResult.confidence must be in [0, 1], got {self.confidence}"
            )
        if not self.reason.strip():
            raise ValueError("DetectionEvaluationResult.reason must be a non-empty string")
