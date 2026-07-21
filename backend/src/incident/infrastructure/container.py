from __future__ import annotations

from incident.application.services.incident_application_service import IncidentApplicationService
from incident.infrastructure.acl.analytics_incident_event_adapter import (
    InMemoryAnalyticsIncidentEventAdapter,
)
from incident.infrastructure.acl.notification_adapters import (
    InMemoryCommunicationNotificationAdapter,
    StubITSMNotificationAdapter,
)
from incident.infrastructure.acl.security_graph_write_adapter import (
    InMemorySecurityGraphWriteAdapter,
)
from incident.infrastructure.observability.metrics_store import OperationalMetricsStore
from incident.infrastructure.persistence.in_memory_repositories import (
    InMemoryCommunicationLogRepository,
    InMemoryContainmentActionRepository,
    InMemoryEradicationVerificationRepository,
    InMemoryIncidentRepository,
    InMemoryRecoveryMilestoneRepository,
)
from incident.infrastructure.workers.incident_workers import (
    AnalyticsPublishingWorker,
    IncidentScheduler,
    RecoveryWorker,
    RetryWorker,
)


class IncidentContainer:
    def __init__(self) -> None:
        self.incidents = InMemoryIncidentRepository()
        self.actions = InMemoryContainmentActionRepository()
        self.eradications = InMemoryEradicationVerificationRepository()
        self.milestones = InMemoryRecoveryMilestoneRepository()
        self.comm_log = InMemoryCommunicationLogRepository()
        self.analytics = InMemoryAnalyticsIncidentEventAdapter()
        self.graph = InMemorySecurityGraphWriteAdapter()
        self.comm_notify = InMemoryCommunicationNotificationAdapter()
        self.itsm = StubITSMNotificationAdapter()
        self.metrics = OperationalMetricsStore()
        self.event_sink: list[object] = []
        self.app = IncidentApplicationService(
            self.incidents,
            self.actions,
            self.eradications,
            self.milestones,
            self.comm_log,
            self.analytics,
            self.graph,
            self.comm_notify,
            self.itsm,
            self.event_sink,
        )
        self.retry_worker = RetryWorker()
        self.recovery_worker = RecoveryWorker(self.app)
        self.analytics_worker = AnalyticsPublishingWorker(self.analytics)
        self.scheduler = IncidentScheduler()
