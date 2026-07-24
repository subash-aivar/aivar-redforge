"""AlertEvaluationResult — the raw output of one `IAlertEvaluator` run
against a `CorrelationResult`.

Deliberately not the `Alert` aggregate itself: the evaluator decides
only whether an alert should exist, at what severity, and whether it
should be suppressed on arrival — `AlertApplicationService` is what
actually calls `Alert.raise_alert()`/`.suppress()`/`.deduplicate()`
(M43A, reused verbatim, never reimplemented here).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from siem_alerting.application.exceptions import InvalidSuppressionDecisionError

if TYPE_CHECKING:
    from siem_alerting.domain.value_objects.enums import AlertSeverity


@dataclass(frozen=True, slots=True)
class AlertEvaluationResult:
    should_alert: bool
    severity: AlertSeverity
    reason: str
    suppress: bool = False
    suppression_reason: str | None = None

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError("AlertEvaluationResult.reason must be a non-empty string")
        if self.suppress and not (self.suppression_reason or "").strip():
            raise InvalidSuppressionDecisionError(
                "suppression_reason is required when suppress=True"
            )
        if not self.suppress and self.suppression_reason is not None:
            raise InvalidSuppressionDecisionError(
                "suppression_reason must be None when suppress=False"
            )
