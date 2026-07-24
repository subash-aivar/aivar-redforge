"""Immutable command-outcome DTOs for the Security Baseline / CSPM
Foundation (M45F). Read-once results returned synchronously to the
caller — never persisted, never carrying compliance results or risk
scores."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_security.application.dtos.baseline_evaluation_record import (
        BaselineEvaluationRecord,
    )


@dataclass(frozen=True, slots=True)
class BaselineCompleted:
    record: BaselineEvaluationRecord


@dataclass(frozen=True, slots=True)
class BaselineStatistics:
    total_evaluations: int
    in_progress_evaluations: int
    completed_evaluations: int
    failed_evaluations: int
    total_assets_evaluated: int
    total_findings: int


class BatchBaselineStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIALLY_SUCCEEDED = "partially_succeeded"


@dataclass(frozen=True, slots=True)
class BatchBaselineFailure:
    index: int
    error_type: str
    message: str


@dataclass(frozen=True, slots=True)
class BatchBaselineResult:
    status: BatchBaselineStatus
    completed: tuple[BaselineCompleted, ...] = field(default_factory=tuple)
    failures: tuple[BatchBaselineFailure, ...] = field(default_factory=tuple)

    @property
    def succeeded_count(self) -> int:
        return len(self.completed)

    @property
    def failed_count(self) -> int:
        return len(self.failures)
