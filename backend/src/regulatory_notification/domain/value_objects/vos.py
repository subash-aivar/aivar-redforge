from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class NotificationDeadline:
    deadline_at: datetime
    deadline_hours: int
    regime: str
    clock_started_at: datetime
    advisory: bool = False


@dataclass(frozen=True, slots=True)
class SubmissionRecord:
    submitted_at: datetime
    submitted_by: str
    submission_method: str
    reference_number: str


@dataclass(frozen=True, slots=True)
class DeadlineBreachRecord:
    breach_detected_at: datetime
    hours_overdue: float
    notification_submitted_before_breach: bool


@dataclass(frozen=True, slots=True)
class NotificationRecipient:
    name: str
    channel: str
    address: str


@dataclass(frozen=True, slots=True)
class NotificationTemplate:
    template_id: str
    regime: str
    body_template: str
