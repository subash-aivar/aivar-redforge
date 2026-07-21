from __future__ import annotations

from dataclasses import dataclass

from regulatory_notification.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class RegulatoryNotificationClockStarted(BaseDomainEvent):
    notification_id: str = ""
    incident_id: str = ""
    regime: str = ""
    deadline_at: str = ""
    clock_started_at: str = ""


@dataclass(frozen=True, slots=True)
class RegulatoryDeadlineApproaching(BaseDomainEvent):
    notification_id: str = ""
    incident_id: str = ""
    regime: str = ""
    deadline_at: str = ""
    hours_remaining: float = 0.0


@dataclass(frozen=True, slots=True)
class RegulatoryDeadlineBreached(BaseDomainEvent):
    notification_id: str = ""
    incident_id: str = ""
    regime: str = ""
    deadline_at: str = ""
    hours_overdue: float = 0.0


@dataclass(frozen=True, slots=True)
class RegulatoryNotificationCreated(BaseDomainEvent):
    notification_id: str = ""
    incident_id: str = ""
    regime: str = ""


@dataclass(frozen=True, slots=True)
class RegulatoryNotificationApproved(BaseDomainEvent):
    notification_id: str = ""
    approved_by: str = ""


@dataclass(frozen=True, slots=True)
class RegulatoryNotificationSubmitted(BaseDomainEvent):
    notification_id: str = ""
    incident_id: str = ""
    regime: str = ""
    submitted_by: str = ""
    submitted_at: str = ""
    reference_number: str = ""


@dataclass(frozen=True, slots=True)
class RegulatoryNotificationAcknowledged(BaseDomainEvent):
    notification_id: str = ""
    acknowledged_by: str = ""
    acknowledged_at: str = ""
