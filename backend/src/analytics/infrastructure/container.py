"""DI container for analytics Phase 1-5."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from analytics.application.services.analytics_application_service import (
    AnalyticsApplicationService,
)
from analytics.infrastructure.acl.ml_anomaly_score_adapter import StubMLAnomalyScoreAdapter
from analytics.infrastructure.acl.security_graph_write_adapter import (
    InMemorySecurityGraphWriteAdapter,
)
from analytics.infrastructure.config import AnalyticsSettings
from analytics.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from analytics.infrastructure.observability.metrics_store import OperationalMetricsStore
from analytics.infrastructure.persistence.in_memory_repositories import (
    InMemoryAnalyticsDataSetRepository,
    InMemoryAnalyticsQueryRepository,
    InMemoryAnomalyDetectionBaselineRepository,
    InMemorySecurityKPIRepository,
)
from analytics.infrastructure.projections.event_projection_store import (
    EventProjectionStore,
)
from analytics.infrastructure.scheduler.analytics_scheduler import AnalyticsScheduler
from analytics.infrastructure.workers.analytics_workers import (
    AnalyticsProjectionWorker,
    KPIComputationWorker,
    PartitionMaintenanceWorker,
    ProjectionRebuildWorker,
    RetentionPolicyWorker,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class AnalyticsContainer:
    # No stable domain ABC covers these 4 (the ones in domain/repositories/
    # are stale — see postgres_repositories.py docstring), so kept as Any
    # rather than typing against either the stale ABC or one concrete impl.
    datasets: Any
    kpis: Any
    baselines: Any
    queries: Any

    def __init__(
        self, session_factory: async_sessionmaker[AsyncSession] | None = None
    ) -> None:
        self.settings = AnalyticsSettings.from_env()
        # EventProjectionStore (raw event ingestion + idempotency +
        # kpi_snapshots/anomalies/checkpoints tracking) is a separate,
        # larger persistence unit than the 4 aggregate repositories below —
        # migration 0091 has real tables for it (processed_analytics_events,
        # kpi_snapshots, anomaly_detections, projection_checkpoints) but
        # converting it is out of scope for this pass; still in-memory.
        self.store = EventProjectionStore()
        if session_factory is not None:
            from analytics.infrastructure.persistence.postgres_repositories import (
                PgAnalyticsDataSetRepository,
                PgAnalyticsQueryRepository,
                PgAnomalyDetectionBaselineRepository,
                PgSecurityKPIRepository,
            )

            self.datasets = PgAnalyticsDataSetRepository(session_factory)
            self.kpis = PgSecurityKPIRepository(session_factory)
            self.baselines = PgAnomalyDetectionBaselineRepository(session_factory)
            self.queries = PgAnalyticsQueryRepository(session_factory)
        else:
            self.datasets = InMemoryAnalyticsDataSetRepository()
            self.kpis = InMemorySecurityKPIRepository()
            self.baselines = InMemoryAnomalyDetectionBaselineRepository()
            self.queries = InMemoryAnalyticsQueryRepository()
        self.event_publisher = StructlogEventPublisher()
        self.graph = InMemorySecurityGraphWriteAdapter()
        self.ml_anomaly = StubMLAnomalyScoreAdapter()
        self.metrics = OperationalMetricsStore()
        self.app = AnalyticsApplicationService(
            self.datasets,
            self.kpis,
            self.baselines,
            self.queries,
            self.store,
            self.event_publisher,
            graph_port=self.graph,
            ml_anomaly_port=self.ml_anomaly,
            metrics=self.metrics,
            settings=self.settings,
        )
        self.projection_worker = AnalyticsProjectionWorker(
            self.app, metrics=self.metrics, max_retries=self.settings.projection_max_retries
        )
        self.kpi_worker = KPIComputationWorker(self.app, metrics=self.metrics)
        self.retention_worker = RetentionPolicyWorker(self.store)
        self.partition_worker = PartitionMaintenanceWorker()
        self.rebuild_worker = ProjectionRebuildWorker(self.app)
        self.scheduler = AnalyticsScheduler(
            self.kpi_worker, self.retention_worker, self.partition_worker
        )
