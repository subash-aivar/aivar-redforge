"""DI container for reporting Phase 2-5."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from reporting.application.services.reporting_application_service import (
    ReportingApplicationService,
)
from reporting.domain.aggregates.report_template import ReportTemplate
from reporting.domain.services.bi_export_rate_limiter import BIExportRateLimiter
from reporting.domain.value_objects.enums import ReportType
from reporting.domain.value_objects.identifiers import ReportTemplateId, TenantId
from reporting.infrastructure.acl.analytics_kpi_query_adapter import (
    StaticAnalyticsKPIQueryAdapter,
)
from reporting.infrastructure.acl.composite_delivery_adapter import (
    CompositeReportDeliveryAdapter,
)
from reporting.infrastructure.acl.email_delivery_adapter import EmailReportDeliveryAdapter
from reporting.infrastructure.acl.in_memory_bi_export_adapter import (
    InMemoryBIExportAdapter,
)
from reporting.infrastructure.acl.ml_signal_query_adapter import StubMLSignalQueryAdapter
from reporting.infrastructure.acl.webhook_delivery_adapter import (
    WebhookReportDeliveryAdapter,
)
from reporting.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from reporting.infrastructure.persistence.delivery_audit_store import DeliveryAuditStore
from reporting.infrastructure.persistence.in_memory_repositories import (
    InMemoryReportInstanceRepository,
    InMemoryReportTemplateRepository,
    InMemoryScheduledReportRepository,
)
from reporting.infrastructure.workers.report_scheduler_worker import ReportSchedulerWorker

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from reporting.domain.ports.i_analytics_kpi_query_port import IAnalyticsKPIQueryPort
    from reporting.domain.ports.i_bi_export_port import IBIExportPort
    from reporting.domain.ports.i_ml_signal_query_port import IMLSignalQueryPort
    from reporting.domain.ports.i_report_delivery_port import IReportDeliveryPort
    from reporting.domain.repositories.i_report_instance_repository import (
        IReportInstanceRepository,
    )
    from reporting.domain.repositories.i_report_template_repository import (
        IReportTemplateRepository,
    )
    from reporting.domain.repositories.i_scheduled_report_repository import (
        IScheduledReportRepository,
    )

_PLATFORM_TEMPLATES: tuple[tuple[ReportType, str, list[str]], ...] = (
    (
        ReportType.SECURITY_PROGRAM_DASHBOARD,
        "Security Program Dashboard",
        ["overview", "kpi_cards", "coverage", "campaigns"],
    ),
    (
        ReportType.EXECUTIVE_SECURITY_REPORT,
        "Executive Security Report",
        ["executive_summary", "mttd_trend", "coverage", "ai_risk"],
    ),
    (
        ReportType.KPI_TREND_REPORT,
        "KPI Trend Report",
        ["trend_charts", "dominant_pattern", "deltas"],
    ),
    (
        ReportType.ANOMALY_SUMMARY_REPORT,
        "Anomaly Summary Report",
        ["anomaly_list", "severity_breakdown", "related_kpis"],
    ),
    (
        ReportType.DETECTION_ANALYTICS_REPORT,
        "Detection Analytics Report",
        ["attck_coverage", "fp_rate_trends", "top_coverage_gaps"],
    ),
    (
        ReportType.CAMPAIGN_EFFECTIVENESS_REPORT,
        "Campaign Effectiveness Report",
        ["success_rate_trends", "technique_coverage_delta"],
    ),
    (
        ReportType.PREDICTIVE_THREAT_FORECAST,
        "Predictive Threat Forecast",
        ["top_techniques", "exploitation_probability", "cold_start_fallback"],
    ),
)


class ReportingContainer:
    template_repo: IReportTemplateRepository
    schedule_repo: IScheduledReportRepository
    instance_repo: IReportInstanceRepository

    def __init__(
        self,
        *,
        template_repo: IReportTemplateRepository | None = None,
        schedule_repo: IScheduledReportRepository | None = None,
        instance_repo: IReportInstanceRepository | None = None,
        kpi_port: IAnalyticsKPIQueryPort | None = None,
        ml_port: IMLSignalQueryPort | None = None,
        delivery_port: IReportDeliveryPort | None = None,
        bi_export_port: IBIExportPort | None = None,
        seed_templates: bool = True,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
    ) -> None:
        if template_repo is not None:
            self.template_repo = template_repo
        elif session_factory is not None:
            from reporting.infrastructure.persistence.postgres_repositories import (
                PgReportTemplateRepository,
            )

            self.template_repo = PgReportTemplateRepository(session_factory)
            # Postgres path can't self-seed synchronously — see
            # api/dependencies.py::get_container, which awaits
            # ensure_templates() after construction.
            seed_templates = False
        else:
            self.template_repo = InMemoryReportTemplateRepository()

        if schedule_repo is not None:
            self.schedule_repo = schedule_repo
        elif session_factory is not None:
            from reporting.infrastructure.persistence.postgres_repositories import (
                PgScheduledReportRepository,
            )

            self.schedule_repo = PgScheduledReportRepository(session_factory)
        else:
            self.schedule_repo = InMemoryScheduledReportRepository()

        if instance_repo is not None:
            self.instance_repo = instance_repo
        elif session_factory is not None:
            from reporting.infrastructure.persistence.postgres_repositories import (
                PgReportInstanceRepository,
            )

            self.instance_repo = PgReportInstanceRepository(session_factory)
        else:
            self.instance_repo = InMemoryReportInstanceRepository()
        self.kpi_port = kpi_port or StaticAnalyticsKPIQueryAdapter()
        self.ml_port = ml_port or StubMLSignalQueryAdapter()
        self.delivery_audit = DeliveryAuditStore()
        self.email_delivery = EmailReportDeliveryAdapter(self.delivery_audit)
        self.webhook_delivery = WebhookReportDeliveryAdapter(self.delivery_audit)
        self.delivery_port = delivery_port or CompositeReportDeliveryAdapter(
            self.email_delivery, self.webhook_delivery
        )
        self.bi_export_port = bi_export_port or InMemoryBIExportAdapter()
        self.rate_limiter = BIExportRateLimiter()
        self.event_publisher = StructlogEventPublisher()
        self.app = ReportingApplicationService(
            self.template_repo,
            self.schedule_repo,
            self.instance_repo,
            self.kpi_port,
            self.ml_port,
            self.delivery_port,
            self.event_publisher,
            bi_export_port=self.bi_export_port,
            rate_limiter=self.rate_limiter,
        )
        self.scheduler_worker = ReportSchedulerWorker(self.app)
        if seed_templates:
            self._seed_platform_templates()

    def _seed_platform_templates(self) -> None:
        now = datetime.now(UTC)
        store = getattr(self.template_repo, "_by_id", None)
        by_type = getattr(self.template_repo, "_by_type", None)
        if store is None or by_type is None:
            return
        for report_type, name, sections in _PLATFORM_TEMPLATES:
            if report_type.value in by_type:
                continue
            tmpl = ReportTemplate.create_platform(
                ReportTemplateId.generate(),
                report_type,
                name,
                sections,
                now,
            )
            store[str(tmpl.template_id)] = tmpl
            by_type[report_type.value] = str(tmpl.template_id)

    async def ensure_templates(self) -> None:
        now = datetime.now(UTC)
        placeholder = TenantId.generate()
        for report_type, name, sections in _PLATFORM_TEMPLATES:
            existing = await self.template_repo.find_by_type_for_tenant(placeholder, report_type)
            if existing is not None:
                continue
            await self.template_repo.save(
                ReportTemplate.create_platform(
                    ReportTemplateId.generate(),
                    report_type,
                    name,
                    sections,
                    now,
                )
            )

    def template_id_for(self, report_type: ReportType) -> str | None:
        by_type = getattr(self.template_repo, "_by_type", None)
        if by_type is None:
            return None
        value = by_type.get(report_type.value)
        return str(value) if value is not None else None
