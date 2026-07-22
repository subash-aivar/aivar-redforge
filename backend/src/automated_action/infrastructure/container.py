from __future__ import annotations

from typing import TYPE_CHECKING

from automated_action.application.services.automation_application_service import (
    AutomationApplicationService,
)
from automated_action.infrastructure.adapters.in_memory_ports import (
    InMemoryConnectorExecutionPort,
    InMemoryPlaybookLookup,
)
from automated_action.infrastructure.observability.metrics_store import OperationalMetricsStore
from automated_action.infrastructure.persistence.in_memory_repositories import (
    InMemoryAutomatedActionRecordRepository,
    InMemoryAutomationExecutionRepository,
    InMemoryRollbackRecordRepository,
)
from automated_action.infrastructure.projectors.analytics_projector import (
    AutomationAnalyticsProjector,
)
from automated_action.infrastructure.projectors.kg_projector import AutomationKGProjector
from automated_action.infrastructure.workers.automation_workers import (
    AutomationScheduler,
    EscalationTimeoutWorker,
    ExecutionScheduler,
    MetricsWorker,
    OutboxRecoveryWorker,
    PlaybookExecutionWorker,
    PlaybookTriggerWorker,
    RecoveryWorker,
    RetryWorker,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from automated_action.domain.repositories.i_automation_repositories import (
        IAutomatedActionRecordRepository,
        IAutomationExecutionRepository,
        IRollbackRecordRepository,
    )


class AutomatedActionContainer:
    executions: IAutomationExecutionRepository
    records: IAutomatedActionRecordRepository
    rollbacks: IRollbackRecordRepository

    def __init__(
        self, session_factory: async_sessionmaker[AsyncSession] | None = None
    ) -> None:
        if session_factory is not None:
            from automated_action.infrastructure.persistence.postgres_repositories import (
                PgAutomatedActionRecordRepository,
                PgAutomationExecutionRepository,
                PgRollbackRecordRepository,
            )

            self.executions = PgAutomationExecutionRepository(session_factory)
            self.records = PgAutomatedActionRecordRepository(session_factory)
            self.rollbacks = PgRollbackRecordRepository(session_factory)
        else:
            self.executions = InMemoryAutomationExecutionRepository()
            self.records = InMemoryAutomatedActionRecordRepository()
            self.rollbacks = InMemoryRollbackRecordRepository()
        self.playbook_lookup = InMemoryPlaybookLookup()
        self.connector_port = InMemoryConnectorExecutionPort()
        self.event_sink: list[object] = []
        self.metrics_store = OperationalMetricsStore()
        self.app = AutomationApplicationService(
            self.executions,
            self.records,
            self.rollbacks,
            self.playbook_lookup,
            self.connector_port,
            self.event_sink,
        )
        self.trigger_worker = PlaybookTriggerWorker(self.app)
        self.execution_worker = PlaybookExecutionWorker(self.app)
        self.escalation_worker = EscalationTimeoutWorker(self.executions)
        self.outbox_worker = OutboxRecoveryWorker(self.records, self.connector_port)
        self.retry_worker = RetryWorker()
        self.recovery_worker = RecoveryWorker()
        self.metrics_worker = MetricsWorker(self.app.metrics)
        self.kg = AutomationKGProjector()
        self.analytics = AutomationAnalyticsProjector()
        self.scheduler = AutomationScheduler(
            ExecutionScheduler(self.execution_worker, self.executions),
            self.escalation_worker,
            self.outbox_worker,
            self.retry_worker,
            self.recovery_worker,
            self.metrics_worker,
        )
