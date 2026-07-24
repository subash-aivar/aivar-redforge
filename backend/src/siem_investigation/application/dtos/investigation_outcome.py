"""Immutable investigation-outcome DTOs (M44D §5).

Read-once outcomes returned synchronously to the caller — never
persisted. The Investigation Engine's responsibility ends at producing
these; it never calculates risk, never scores executively, never
implements search or analytics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class InvestigationOutcomeStatus(StrEnum):
    OPENED = "opened"
    UPDATED = "updated"
    REJECTED = "rejected"
    FAILED = "failed"
    UNSUPPORTED_EVALUATOR = "unsupported_evaluator"
    SUCCEEDED = "succeeded"
    PARTIALLY_SUCCEEDED = "partially_succeeded"


@dataclass(frozen=True, slots=True)
class InvestigationFailure:
    stage: str
    error_type: str
    message: str


_TIMELINE_ID_STATUSES = frozenset(
    {InvestigationOutcomeStatus.OPENED, InvestigationOutcomeStatus.UPDATED}
)


@dataclass(frozen=True, slots=True)
class InvestigationOutcome:
    status: InvestigationOutcomeStatus
    timeline_id: str | None = None
    scope_ref: str | None = None
    entry_count: int | None = None
    decision_reason: str | None = None
    failures: tuple[InvestigationFailure, ...] = ()

    def __post_init__(self) -> None:
        timeline_id_required = self.status in _TIMELINE_ID_STATUSES
        if timeline_id_required and self.timeline_id is None:
            raise ValueError(f"{self.status} InvestigationOutcome must carry a timeline_id")
        if not timeline_id_required and self.timeline_id is not None:
            raise ValueError(f"{self.status} InvestigationOutcome must not carry a timeline_id")


@dataclass(frozen=True, slots=True)
class BatchInvestigationResult:
    status: InvestigationOutcomeStatus
    outcomes: tuple[InvestigationOutcome, ...] = field(default_factory=tuple)

    @property
    def opened_or_updated_count(self) -> int:
        return sum(1 for o in self.outcomes if o.status in _TIMELINE_ID_STATUSES)

    @property
    def failed_count(self) -> int:
        return sum(1 for o in self.outcomes if o.status == InvestigationOutcomeStatus.FAILED)
