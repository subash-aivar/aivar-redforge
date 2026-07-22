from __future__ import annotations

from typing import TYPE_CHECKING

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

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from incident.domain.repositories.i_incident_repositories import (
        IContainmentActionRepository,
        IEradicationVerificationRepository,
        IIncidentCommunicationLogRepository,
        IIncidentRepository,
        IRecoveryMilestoneRepository,
    )


class IncidentContainer:
    """Wires the incident bounded context.

    session_factory=None keeps the historical in-memory repositories, which
    exist for fast unit tests (see tests/incident/test_lifecycle.py) that
    don't stand up a database. Passing a real session_factory — as the API
    layer does in incident/api/dependencies.py — switches every repository
    to its PostgreSQL-backed implementation so incident data survives a
    process restart.
    """

    incidents: IIncidentRepository
    actions: IContainmentActionRepository
    eradications: IEradicationVerificationRepository
    milestones: IRecoveryMilestoneRepository
    comm_log: IIncidentCommunicationLogRepository

    def __init__(
        self, session_factory: async_sessionmaker[AsyncSession] | None = None
    ) -> None:
        if session_factory is not None:
            from incident.infrastructure.persistence.postgres_repositories import (
                PgContainmentActionRepository,
                PgEradicationVerificationRepository,
                PgIncidentCommunicationLogRepository,
                PgIncidentRepository,
                PgRecoveryMilestoneRepository,
            )

            self.incidents = PgIncidentRepository(session_factory)
            self.actions = PgContainmentActionRepository(session_factory)
            self.eradications = PgEradicationVerificationRepository(session_factory)
            self.milestones = PgRecoveryMilestoneRepository(session_factory)
            self.comm_log = PgIncidentCommunicationLogRepository(session_factory)
        else:
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
