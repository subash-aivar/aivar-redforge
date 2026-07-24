"""InvestigationEvaluationResult — the raw output of one
`IInvestigationEvaluator` run against an `Alert`.

Deliberately not the `InvestigationTimeline` aggregate itself: the
evaluator decides only whether the alert should open/update an
investigation, under what scope, and what to record — the application
service is what actually calls `InvestigationTimeline.create()`/
`.add_entry()` (M43A, reused verbatim, never reimplemented here).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from siem_investigation.domain.value_objects.enums import TimelineScopeType


@dataclass(frozen=True, slots=True)
class InvestigationEvaluationResult:
    should_investigate: bool
    scope_type: TimelineScopeType
    scope_ref: str
    summary: str
    reason: str

    def __post_init__(self) -> None:
        if not self.scope_ref.strip():
            raise ValueError("InvestigationEvaluationResult.scope_ref must be a non-empty string")
        if not self.summary.strip():
            raise ValueError("InvestigationEvaluationResult.summary must be a non-empty string")
        if not self.reason.strip():
            raise ValueError("InvestigationEvaluationResult.reason must be a non-empty string")
