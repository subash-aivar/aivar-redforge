"""CorrelationEvaluationResult — the raw output of one
`ICorrelationEvaluator` run against a session's accumulated events.

Deliberately not a `CorrelationResult` itself: the evaluator decides
only whether the accumulated pattern now matches; the application
service is what turns a positive result into the application-facing
`CorrelationResult` DTO (session id, window metadata are context the
evaluator doesn't need to know about).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CorrelationEvaluationResult:
    matched: bool
    confidence: float
    reason: str

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"CorrelationEvaluationResult.confidence must be in [0, 1], got {self.confidence}"
            )
        if not self.reason.strip():
            raise ValueError("CorrelationEvaluationResult.reason must be a non-empty string")
