from __future__ import annotations

from regulatory_notification.application.services.regulatory_application_service import (
    RegulatoryApplicationService,
)
from regulatory_notification.domain.services.deadline_alerting_service import (
    DeadlineAlertingService,
)
from regulatory_notification.infrastructure.acl.deadline_alert_adapter import (
    InMemoryDeadlineAlertNotificationAdapter,
)
from regulatory_notification.infrastructure.persistence.in_memory_repositories import (
    InMemoryNotificationDeadlineRepository,
    InMemoryNotificationDraftRepository,
    InMemoryRegulatoryNotificationRepository,
)
from regulatory_notification.infrastructure.workers.deadline_worker import (
    DeadlineAlertingWorker,
    RegulatoryScheduler,
)


class RegulatoryNotificationContainer:
    def __init__(self) -> None:
        self.notifications = InMemoryRegulatoryNotificationRepository()
        self.drafts = InMemoryNotificationDraftRepository()
        self.deadlines = InMemoryNotificationDeadlineRepository()
        self.alert_port = InMemoryDeadlineAlertNotificationAdapter()
        self.alerting = DeadlineAlertingService()
        self.app = RegulatoryApplicationService(
            self.notifications, self.drafts, self.deadlines, self.alert_port
        )
        self.deadline_worker = DeadlineAlertingWorker(
            self.notifications, self.alerting, self.alert_port, self.deadlines
        )
        self.scheduler = RegulatoryScheduler(self.deadline_worker)
