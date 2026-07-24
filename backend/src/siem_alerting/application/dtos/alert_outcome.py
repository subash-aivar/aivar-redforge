"""Immutable alert-outcome DTOs (M44C §5).

Read-once outcomes returned synchronously to the caller — never
persisted. The Alert Engine's responsibility ends at producing these;
it never opens an Investigation, never scores risk.

Named `AlertOutcomeStatus`, not `AlertStatus`, to avoid any collision
with the `Alert` aggregate's own domain-level `AlertStatus` (M43A) —
this status describes the *application-layer outcome* of one
evaluation call, not the aggregate's lifecycle state (though the two
are related: `CREATED` ⇒ the alert is `RAISED`, `SUPPRESSED` ⇒
`SUPPRESSED`, `DEDUPLICATED` ⇒ `DEDUPLICATED`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class AlertOutcomeStatus(StrEnum):
    CREATED = "created"
    SUPPRESSED = "suppressed"
    DEDUPLICATED = "deduplicated"
    REJECTED = "rejected"
    FAILED = "failed"
    UNSUPPORTED_EVALUATOR = "unsupported_evaluator"
    SUCCEEDED = "succeeded"
    PARTIALLY_SUCCEEDED = "partially_succeeded"


@dataclass(frozen=True, slots=True)
class AlertFailure:
    stage: str
    error_type: str
    message: str


_ALERT_ID_STATUSES = frozenset(
    {AlertOutcomeStatus.CREATED, AlertOutcomeStatus.SUPPRESSED, AlertOutcomeStatus.DEDUPLICATED}
)


@dataclass(frozen=True, slots=True)
class AlertOutcome:
    status: AlertOutcomeStatus
    alert_id: str | None = None
    dedup_key: str | None = None
    original_alert_id: str | None = None
    decision_reason: str | None = None
    failures: tuple[AlertFailure, ...] = ()

    def __post_init__(self) -> None:
        alert_id_required = self.status in _ALERT_ID_STATUSES
        if alert_id_required and self.alert_id is None:
            raise ValueError(f"{self.status} AlertOutcome must carry an alert_id")
        if not alert_id_required and self.alert_id is not None:
            raise ValueError(f"{self.status} AlertOutcome must not carry an alert_id")
        if self.original_alert_id is not None and self.status != AlertOutcomeStatus.DEDUPLICATED:
            raise ValueError("original_alert_id is only valid for a DEDUPLICATED AlertOutcome")


@dataclass(frozen=True, slots=True)
class BatchAlertResult:
    status: AlertOutcomeStatus
    outcomes: tuple[AlertOutcome, ...] = field(default_factory=tuple)

    @property
    def created_count(self) -> int:
        return sum(
            1
            for o in self.outcomes
            if o.status in (AlertOutcomeStatus.CREATED, AlertOutcomeStatus.DEDUPLICATED)
        )

    @property
    def failed_count(self) -> int:
        return sum(1 for o in self.outcomes if o.status == AlertOutcomeStatus.FAILED)
