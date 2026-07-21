from __future__ import annotations

from datetime import datetime
from typing import Any

from regulatory_notification.domain.events.regulatory_events import (
    RegulatoryNotificationAcknowledged,
    RegulatoryNotificationClockStarted,
    RegulatoryNotificationCreated,
    RegulatoryNotificationSubmitted,
)
from regulatory_notification.domain.exceptions.domain_exceptions import (
    DomainInvariantViolation,
    InvalidNotificationTransition,
    TenantMismatch,
)
from regulatory_notification.domain.value_objects.enums import NotificationStatus, RegulatoryRegime
from regulatory_notification.domain.value_objects.identifiers import RegNotificationId, TenantId
from regulatory_notification.domain.value_objects.vos import (
    DeadlineBreachRecord,
    NotificationDeadline,
    SubmissionRecord,
)


class RegulatoryNotification:
    def __init__(
        self,
        notification_id: RegNotificationId,
        tenant_id: TenantId,
        incident_id: str,
        regime: RegulatoryRegime,
        jurisdiction: str,
        deadline: NotificationDeadline,
        status: NotificationStatus,
        *,
        draft_ref: str | None = None,
        submission_record: SubmissionRecord | None = None,
        deadline_breach_records: list[DeadlineBreachRecord] | None = None,
    ) -> None:
        self.notification_id = notification_id
        self.tenant_id = tenant_id
        self.incident_id = incident_id
        self.regime = regime
        self.jurisdiction = jurisdiction
        self.deadline = deadline
        self.status = status
        self.draft_ref = draft_ref
        self.submission_record = submission_record
        self.deadline_breach_records = list(deadline_breach_records or [])
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        ev = list(self._pending_events)
        self._pending_events.clear()
        return ev

    @classmethod
    def start_clock(
        cls,
        notification_id: RegNotificationId,
        tenant_id: TenantId,
        incident_id: str,
        regime: RegulatoryRegime,
        jurisdiction: str,
        deadline: NotificationDeadline,
    ) -> RegulatoryNotification:
        n = cls(
            notification_id,
            tenant_id,
            incident_id,
            regime,
            jurisdiction,
            deadline,
            NotificationStatus.CLOCK_STARTED,
        )
        n._pending_events.append(
            RegulatoryNotificationCreated(
                tenant_id=str(tenant_id),
                aggregate_id=str(notification_id),
                notification_id=str(notification_id),
                incident_id=incident_id,
                regime=regime.value,
            )
        )
        n._pending_events.append(
            RegulatoryNotificationClockStarted(
                tenant_id=str(tenant_id),
                aggregate_id=str(notification_id),
                notification_id=str(notification_id),
                incident_id=incident_id,
                regime=regime.value,
                deadline_at=deadline.deadline_at.isoformat(),
                clock_started_at=deadline.clock_started_at.isoformat(),
            )
        )
        return n

    def mark_draft_in_progress(self, tenant_id: TenantId, draft_ref: str) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        if self.status not in {
            NotificationStatus.CLOCK_STARTED,
            NotificationStatus.DRAFT_IN_PROGRESS,
        }:
            raise InvalidNotificationTransition()
        self.status = NotificationStatus.DRAFT_IN_PROGRESS
        self.draft_ref = draft_ref

    def mark_ready(self, tenant_id: TenantId) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        if self.status in {
            NotificationStatus.SUBMITTED,
            NotificationStatus.ACKNOWLEDGED,
        }:
            raise InvalidNotificationTransition("cannot mark ready after submit")
        if self.status == NotificationStatus.CLOCK_STARTED:
            self.status = NotificationStatus.DRAFT_IN_PROGRESS
        if self.status not in {
            NotificationStatus.DRAFT_IN_PROGRESS,
            NotificationStatus.READY_FOR_SUBMISSION,
        }:
            raise InvalidNotificationTransition(f"cannot mark ready from {self.status.value}")
        self.status = NotificationStatus.READY_FOR_SUBMISSION

    def submit(
        self,
        tenant_id: TenantId,
        submitted_by: str,
        submission_method: str,
        reference_number: str,
        at: datetime,
    ) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        if self.submission_record is not None:
            raise DomainInvariantViolation("SubmissionRecord immutable — already set")
        if self.status in {
            NotificationStatus.SUBMITTED,
            NotificationStatus.ACKNOWLEDGED,
        }:
            raise InvalidNotificationTransition(f"invalid status for submit: {self.status.value}")
        if self.status != NotificationStatus.READY_FOR_SUBMISSION:
            # allow human submit after draft workflow; auto-promote ready
            if self.status in {
                NotificationStatus.CLOCK_STARTED,
                NotificationStatus.DRAFT_IN_PROGRESS,
            }:
                self.status = NotificationStatus.READY_FOR_SUBMISSION
            else:
                raise InvalidNotificationTransition(
                    f"invalid status for submit: {self.status.value}"
                )
        self.submission_record = SubmissionRecord(
            at, submitted_by, submission_method, reference_number
        )
        self.status = NotificationStatus.SUBMITTED
        self._pending_events.append(
            RegulatoryNotificationSubmitted(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.notification_id),
                notification_id=str(self.notification_id),
                incident_id=self.incident_id,
                regime=self.regime.value,
                submitted_by=submitted_by,
                submitted_at=at.isoformat(),
                reference_number=reference_number,
            )
        )

    def acknowledge(self, tenant_id: TenantId, acknowledged_by: str, at: datetime) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        if self.status != NotificationStatus.SUBMITTED:
            raise InvalidNotificationTransition()
        self.status = NotificationStatus.ACKNOWLEDGED
        self._pending_events.append(
            RegulatoryNotificationAcknowledged(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.notification_id),
                notification_id=str(self.notification_id),
                acknowledged_by=acknowledged_by,
                acknowledged_at=at.isoformat(),
            )
        )

    def record_breach(self, at: datetime, hours_overdue: float) -> None:
        self.deadline_breach_records.append(
            DeadlineBreachRecord(at, hours_overdue, self.submission_record is not None)
        )
