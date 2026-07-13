"""Validation Run aggregate root.

A ValidationRun represents a single execution of security validation
against an AI Target. It tracks the lifecycle from scheduling through
completion or failure, and holds the summary of results.

This entity models the business workflow — NOT the execution engine.
The actual attack execution is an infrastructure concern.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.validations.events import (
    ValidationCancelled,
    ValidationCompleted,
    ValidationEvent,
    ValidationFailed,
    ValidationRetried,
    ValidationScheduled,
    ValidationStarted,
    _now,
)
from redforge.domain.validations.exceptions import (
    InvalidValidationTransitionError,
    ValidationAlreadyCompleteError,
)
from redforge.domain.validations.value_objects import (
    TriggerType,
    ValidationStatus,
    ValidationSummary,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps

if TYPE_CHECKING:
    from datetime import datetime


class ValidationRun:
    """Validation Run aggregate root.

    Invariants:
    - Always belongs to an Organization and targets an AITarget.
    - Status transitions follow a defined state machine.
    - Terminal states (COMPLETED, FAILED, CANCELLED) are immutable.
    - Summary can only be attached to a COMPLETED run.
    - started_at is set when transitioning to RUNNING.
    - completed_at is set when reaching a terminal state.
    """

    __slots__ = (
        "_completed_at",
        "_events",
        "_failure_reason",
        "_id",
        "_organization_id",
        "_policy_id",
        "_started_at",
        "_status",
        "_summary",
        "_target_id",
        "_timestamps",
        "_trigger_type",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        target_id: EntityId,
        policy_id: str | None,
        trigger_type: TriggerType,
        status: ValidationStatus,
        started_at: datetime | None,
        completed_at: datetime | None,
        summary: ValidationSummary | None,
        failure_reason: str | None,
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._target_id = target_id
        self._policy_id = policy_id
        self._trigger_type = trigger_type
        self._status = status
        self._started_at = started_at
        self._completed_at = completed_at
        self._summary = summary
        self._failure_reason = failure_reason
        self._timestamps = timestamps
        self._events: list[ValidationEvent] = []

    @classmethod
    def schedule(
        cls,
        organization_id: EntityId,
        target_id: EntityId,
        trigger_type: TriggerType,
        policy_id: str | None = None,
    ) -> ValidationRun:
        """Schedule a new validation run.

        Starts in SCHEDULED state awaiting execution.
        """
        run = cls(
            id=EntityId.generate(),
            organization_id=organization_id,
            target_id=target_id,
            policy_id=policy_id,
            trigger_type=trigger_type,
            status=ValidationStatus.SCHEDULED,
            started_at=None,
            completed_at=None,
            summary=None,
            failure_reason=None,
            timestamps=AuditTimestamps.create(),
        )
        run._record_event(
            ValidationScheduled(
                occurred_at=_now(),
                run_id=str(run._id),
                target_id=str(target_id),
                organization_id=str(organization_id),
                trigger_type=str(trigger_type),
            )
        )
        return run

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def target_id(self) -> EntityId:
        return self._target_id

    @property
    def policy_id(self) -> str | None:
        return self._policy_id

    @property
    def trigger_type(self) -> TriggerType:
        return self._trigger_type

    @property
    def status(self) -> ValidationStatus:
        return self._status

    @property
    def started_at(self) -> datetime | None:
        return self._started_at

    @property
    def completed_at(self) -> datetime | None:
        return self._completed_at

    @property
    def summary(self) -> ValidationSummary | None:
        return self._summary

    @property
    def failure_reason(self) -> str | None:
        return self._failure_reason

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_terminal(self) -> bool:
        """Whether the run is in a terminal (immutable) state."""
        return self._status in {
            ValidationStatus.COMPLETED,
            ValidationStatus.FAILED,
            ValidationStatus.CANCELLED,
        }

    # ─── Behavior ─────────────────────────────────────────────────────────

    def start(self) -> None:
        """Begin execution of the validation run.

        Transitions: SCHEDULED → RUNNING
        Sets started_at timestamp.
        """
        self._transition_to(ValidationStatus.RUNNING)
        self._started_at = _now()
        self._record_event(
            ValidationStarted(
                occurred_at=_now(),
                run_id=str(self._id),
                target_id=str(self._target_id),
            )
        )

    def complete(self) -> None:
        """Mark the validation run as successfully completed.

        Transitions: RUNNING → COMPLETED
        Sets completed_at timestamp.
        """
        self._transition_to(ValidationStatus.COMPLETED)
        self._completed_at = _now()
        self._record_event(
            ValidationCompleted(
                occurred_at=_now(),
                run_id=str(self._id),
                target_id=str(self._target_id),
                total_checks=self._summary.total_checks if self._summary else 0,
                passed=self._summary.passed if self._summary else 0,
                failed=self._summary.failed if self._summary else 0,
            )
        )

    def fail(self, reason: str) -> None:
        """Mark the validation run as failed.

        Transitions: SCHEDULED → FAILED, RUNNING → FAILED
        Sets completed_at timestamp and failure reason.
        """
        self._transition_to(ValidationStatus.FAILED)
        self._failure_reason = reason
        self._completed_at = _now()
        self._record_event(
            ValidationFailed(
                occurred_at=_now(),
                run_id=str(self._id),
                target_id=str(self._target_id),
                reason=reason,
            )
        )

    def cancel(self) -> None:
        """Cancel the validation run.

        Transitions: SCHEDULED → CANCELLED, RUNNING → CANCELLED
        Sets completed_at timestamp.
        """
        self._transition_to(ValidationStatus.CANCELLED)
        self._completed_at = _now()
        self._record_event(
            ValidationCancelled(
                occurred_at=_now(),
                run_id=str(self._id),
                target_id=str(self._target_id),
            )
        )

    def retry(self) -> ValidationRun:
        """Create a new validation run as a retry of this failed run.

        Only FAILED runs can be retried. Returns a new ValidationRun
        in SCHEDULED state.
        """
        if self._status != ValidationStatus.FAILED:
            raise InvalidValidationTransitionError(str(self._status), "retry")

        new_run = ValidationRun.schedule(
            organization_id=self._organization_id,
            target_id=self._target_id,
            trigger_type=self._trigger_type,
            policy_id=self._policy_id,
        )
        # Replace the scheduled event with a retry event
        new_run._events.clear()
        new_run._record_event(
            ValidationRetried(
                occurred_at=_now(),
                run_id=str(new_run._id),
                original_run_id=str(self._id),
                target_id=str(self._target_id),
            )
        )
        return new_run

    def attach_summary(self, summary: ValidationSummary) -> None:
        """Attach execution summary to a running validation.

        Summary is attached before marking complete, so the complete
        event can include the metrics.
        """
        if self.is_terminal:
            raise ValidationAlreadyCompleteError(str(self._id))
        if self._status != ValidationStatus.RUNNING:
            raise InvalidValidationTransitionError(
                str(self._status), "attach_summary"
            )
        self._summary = summary
        self._touch()

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[ValidationEvent]:
        """Return and clear all pending domain events."""
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _transition_to(self, target: ValidationStatus) -> None:
        if self.is_terminal:
            raise ValidationAlreadyCompleteError(str(self._id))
        if not self._can_transition_to(target):
            raise InvalidValidationTransitionError(str(self._status), str(target))
        self._status = target
        self._touch()

    def _can_transition_to(self, target: ValidationStatus) -> bool:
        """Valid transitions:
        SCHEDULED → RUNNING, FAILED, CANCELLED
        RUNNING → COMPLETED, FAILED, CANCELLED
        """
        valid: dict[ValidationStatus, set[ValidationStatus]] = {
            ValidationStatus.SCHEDULED: {
                ValidationStatus.RUNNING,
                ValidationStatus.FAILED,
                ValidationStatus.CANCELLED,
            },
            ValidationStatus.RUNNING: {
                ValidationStatus.COMPLETED,
                ValidationStatus.FAILED,
                ValidationStatus.CANCELLED,
            },
        }
        return target in valid.get(self._status, set())

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: ValidationEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ValidationRun):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"ValidationRun(id={self._id}, target={self._target_id}, "
            f"status={self._status})"
        )
