"""DI container for exposure_reporting Phase 5."""

from __future__ import annotations

from typing import TYPE_CHECKING

from exposure_reporting.application.services.business_impact_mapping_service import (
    BusinessImpactMappingService,
)
from exposure_reporting.application.services.dashboard_query_service import (
    DashboardQueryService,
)
from exposure_reporting.application.services.export_service import ReportExportService
from exposure_reporting.application.services.exposure_report_generation_service import (
    ExposureReportGenerationService,
)
from exposure_reporting.application.services.projection_rebuild_service import (
    ProjectionRebuildService,
)
from exposure_reporting.infrastructure.acl.exposure_data_query_adapter import (
    StaticExposureDataQueryAdapter,
)
from exposure_reporting.infrastructure.acl.security_graph_write_adapter import (
    InMemorySecurityGraphWriteAdapter,
)
from exposure_reporting.infrastructure.config import ExposureReportingSettings
from exposure_reporting.infrastructure.events.score_computed_subscriber import (
    ExposureScoreComputedSubscriber,
)
from exposure_reporting.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from exposure_reporting.infrastructure.observability.metrics import ReportingMetrics
from exposure_reporting.infrastructure.persistence.in_memory_repositories import (
    InMemoryBusinessImpactMappingRepository,
    InMemoryExposureReportRepository,
)
from exposure_reporting.infrastructure.projections.kpi_projection_store import (
    KpiProjectionStore,
)
from exposure_reporting.infrastructure.projections.trend_projection_store import (
    TrendProjectionStore,
)
from exposure_reporting.infrastructure.workers.reporting_worker import (
    ReportingBackgroundWorker,
)

if TYPE_CHECKING:
    from exposure_reporting.application.ports.i_exposure_data_query_port import (
        IExposureDataQueryPort,
    )
    from exposure_reporting.domain.ports.i_security_graph_write_port import (
        ISecurityGraphWritePort,
    )
    from exposure_reporting.domain.repositories.i_business_impact_mapping_repository import (
        IBusinessImpactMappingRepository,
    )
    from exposure_reporting.domain.repositories.i_exposure_report_repository import (
        IExposureReportRepository,
    )


class ExposureReportingContainer:
    def __init__(
        self,
        *,
        report_repo: IExposureReportRepository | None = None,
        mapping_repo: IBusinessImpactMappingRepository | None = None,
        exposure_port: IExposureDataQueryPort | None = None,
        graph_port: ISecurityGraphWritePort | None = None,
        settings: ExposureReportingSettings | None = None,
    ) -> None:
        self.settings = settings or ExposureReportingSettings.from_env()
        self.metrics = ReportingMetrics(labels={"context": "exposure_reporting", "phase": "5"})
        self.report_repo = report_repo or InMemoryExposureReportRepository()
        self.mapping_repo = mapping_repo or InMemoryBusinessImpactMappingRepository()
        self.exposure_port = exposure_port or StaticExposureDataQueryAdapter()
        self.graph_port = graph_port or InMemorySecurityGraphWriteAdapter()
        self.event_publisher = StructlogEventPublisher()
        self.kpi_store = KpiProjectionStore()
        self.trend_store = TrendProjectionStore()
        self.mapping_service = BusinessImpactMappingService(self.mapping_repo, self.event_publisher)
        self.report_service = ExposureReportGenerationService(
            self.report_repo,
            self.mapping_repo,
            self.exposure_port,
            self.graph_port,
            self.event_publisher,
        )
        self.dashboard = DashboardQueryService(
            self.exposure_port,
            self.mapping_repo,
            self.kpi_store,
            self.trend_store,
        )
        self.export_service = ReportExportService(self.report_repo)
        self.projections = ProjectionRebuildService(
            self.exposure_port,
            self.mapping_repo,
            self.report_repo,
            self.kpi_store,
            self.trend_store,
            self.graph_port,
        )
        self.score_subscriber = ExposureScoreComputedSubscriber(self.dashboard)
        self.worker = ReportingBackgroundWorker(
            self.report_service, self.dashboard, self.projections
        )
