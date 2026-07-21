"""Campaign domain entities."""

from __future__ import annotations

from typing import TYPE_CHECKING

from campaign.domain.value_objects.campaign_vos import (
    ApprovalRecord,
    ObjectiveEvaluationCriteria,
)
from campaign.domain.value_objects.enums import ObjectiveState, ObjectiveType
from campaign.domain.value_objects.identifiers import (
    CampaignApprovalId,
    CampaignObjectiveId,
)

if TYPE_CHECKING:
    from datetime import datetime

    from campaign.domain.value_objects.campaign_vos import RecurrencePolicy


class CampaignObjective:
    """A specific measurable goal for the campaign.

    Objectives are sealed (made immutable) once the campaign transitions to
    PendingApproval. Sealing prevents post-approval scope changes to objectives.
    """

    __slots__ = (
        "description",
        "evaluation_criteria",
        "id",
        "objective_type",
        "sealed",
        "state",
    )

    def __init__(
        self,
        id: CampaignObjectiveId,
        objective_type: ObjectiveType,
        description: str,
        evaluation_criteria: ObjectiveEvaluationCriteria,
        state: ObjectiveState,
        sealed: bool,
    ) -> None:
        self.id = id
        self.objective_type = objective_type
        self.description = description
        self.evaluation_criteria = evaluation_criteria
        self.state = state
        self.sealed = sealed

    def seal(self) -> None:
        self.sealed = True

    def mark_achieved(self) -> None:
        self.state = ObjectiveState.ACHIEVED

    def mark_failed(self) -> None:
        self.state = ObjectiveState.FAILED

    def mark_skipped(self) -> None:
        self.state = ObjectiveState.SKIPPED

    def mark_inconclusive(self) -> None:
        self.state = ObjectiveState.INCONCLUSIVE


class CampaignApproval:
    """A single approver's formal approval record for a campaign.

    Once granted, an approval can be revoked but not deleted. Revocation
    may drop quorum and revert the campaign to Draft state.
    """

    __slots__ = (
        "id",
        "record",
        "revoked",
        "revoked_at",
        "revoked_by",
    )

    def __init__(
        self,
        id: CampaignApprovalId,
        record: ApprovalRecord,
        revoked: bool = False,
        revoked_at: datetime | None = None,
        revoked_by: str | None = None,
    ) -> None:
        self.id = id
        self.record = record
        self.revoked = revoked
        self.revoked_at = revoked_at
        self.revoked_by = revoked_by


class CampaignSchedule:
    """Recurrence schedule for a Recurring campaign."""

    __slots__ = (
        "blackout_periods",
        "consecutive_failure_count",
        "cron_expression",
        "execution_window_hours",
        "max_consecutive_failures",
    )

    def __init__(
        self,
        cron_expression: str,
        execution_window_hours: int,
        max_consecutive_failures: int,
        blackout_periods: list[str],
        consecutive_failure_count: int = 0,
    ) -> None:
        self.cron_expression = cron_expression
        self.execution_window_hours = execution_window_hours
        self.max_consecutive_failures = max_consecutive_failures
        self.blackout_periods = list(blackout_periods)
        self.consecutive_failure_count = consecutive_failure_count

    def record_failure(self) -> None:
        self.consecutive_failure_count += 1

    def reset_failure_count(self) -> None:
        self.consecutive_failure_count = 0

    def is_failure_threshold_exceeded(self) -> bool:
        return self.consecutive_failure_count >= self.max_consecutive_failures

    def to_recurrence_policy(self) -> RecurrencePolicy:
        """Convert to RecurrencePolicy value object for port/service calls."""
        from campaign.domain.value_objects.campaign_vos import RecurrencePolicy

        return RecurrencePolicy(
            cron_expression=self.cron_expression,
            execution_window_hours=self.execution_window_hours,
            max_consecutive_failures=self.max_consecutive_failures,
            blackout_periods=list(self.blackout_periods),
        )
