"""Evaluation bounded context enumerations."""

from __future__ import annotations

from enum import StrEnum


class EvaluationState(StrEnum):
    PENDING = "Pending"
    EVALUATING = "Evaluating"
    COMPLETE = "Complete"
    REQUIRES_REVIEW = "RequiresReview"


class CompositeOutcome(StrEnum):
    """Deterministic composite campaign outcome computed from ObjectiveAssessments."""

    FULL_SUCCESS = "FullSuccess"
    PARTIAL_SUCCESS = "PartialSuccess"
    OBJECTIVES_MISSED = "ObjectivesMissed"
    EXECUTION_FAILED = "ExecutionFailed"
    INCONCLUSIVE = "Inconclusive"


class ObjectiveOutcome(StrEnum):
    ACHIEVED = "Achieved"
    FAILED = "Failed"
    INCONCLUSIVE = "Inconclusive"
    SKIPPED = "Skipped"
