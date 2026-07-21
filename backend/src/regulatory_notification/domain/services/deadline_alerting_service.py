from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from regulatory_notification.domain.events.regulatory_events import (
    RegulatoryDeadlineApproaching,
    RegulatoryDeadlineBreached,
)
from regulatory_notification.domain.value_objects.enums import DeadlineStatus, NotificationStatus

_THRESHOLDS = (48, 24, 12, 6, 1)


class DeadlineAlertingService:
    def __init__(self) -> None:
        self._sent: set[str] = set()
        self.reconstituted = False

    def reconstitute_on_startup(
        self, notifications: list[Any], now: datetime | None = None
    ) -> list[Any]:
        self.reconstituted = True
        return self.evaluate(notifications, now or datetime.now(UTC))

    def evaluate(self, notifications: list[Any], now: datetime) -> list[Any]:
        events: list[Any] = []
        for n in notifications:
            if n.status in {NotificationStatus.SUBMITTED, NotificationStatus.ACKNOWLEDGED}:
                continue
            deadline_at = n.deadline.deadline_at
            hours_remaining = (deadline_at - now).total_seconds() / 3600.0
            if hours_remaining < 0:
                key = f"{n.notification_id}:breach"
                if key not in self._sent:
                    self._sent.add(key)
                    n.record_breach(now, abs(hours_remaining))
                    events.append(
                        RegulatoryDeadlineBreached(
                            tenant_id=str(n.tenant_id),
                            aggregate_id=str(n.notification_id),
                            notification_id=str(n.notification_id),
                            incident_id=n.incident_id,
                            regime=n.regime.value,
                            deadline_at=deadline_at.isoformat(),
                            hours_overdue=abs(hours_remaining),
                        )
                    )
                continue
            for th in _THRESHOLDS:
                if hours_remaining <= th:
                    key = f"{n.notification_id}:t{th}"
                    if key not in self._sent:
                        self._sent.add(key)
                        events.append(
                            RegulatoryDeadlineApproaching(
                                tenant_id=str(n.tenant_id),
                                aggregate_id=str(n.notification_id),
                                notification_id=str(n.notification_id),
                                incident_id=n.incident_id,
                                regime=n.regime.value,
                                deadline_at=deadline_at.isoformat(),
                                hours_remaining=hours_remaining,
                            )
                        )
                    break
        return events

    def status_for(self, deadline_at: datetime, now: datetime) -> DeadlineStatus:
        hours = (deadline_at - now).total_seconds() / 3600.0
        if hours < 0:
            return DeadlineStatus.BREACHED
        # approximate buffer using remaining hours
        if hours <= 6:
            return DeadlineStatus.AT_RISK
        if hours <= 24:
            return DeadlineStatus.APPROACHING
        return DeadlineStatus.PENDING
