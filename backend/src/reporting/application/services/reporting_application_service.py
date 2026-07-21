"""Application service — auth + report schedule/generation wiring."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from reporting.application._auth import require_at_least
from reporting.application.dtos.reporting_dtos import ReportInstanceDTO, ScheduledReportDTO
from reporting.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationRateLimitedError,
    ApplicationValidationError,
)
from reporting.domain.exceptions.domain_exceptions import ReportingDomainError
from reporting.domain.ports.i_bi_export_port import BIExportRequest, IBIExportPort
from reporting.domain.services.bi_export_rate_limiter import BIExportRateLimiter
from reporting.domain.services.report_export_service import ReportExportService
from reporting.domain.services.report_generation_service import ReportGenerationService
from reporting.domain.services.scheduled_report_service import ScheduledReportService
from reporting.domain.value_objects.enums import AnalyticsRole, ReportFormat, ReportTrigger
from reporting.domain.value_objects.identifiers import (
    ReportInstanceId,
    ReportTemplateId,
    TenantId,
)

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from reporting.application.commands.reporting_commands import (
        CreateScheduledReportCommand,
        GenerateReportOnDemandCommand,
    )
    from reporting.application.ports.i_event_publisher import IEventPublisher
    from reporting.domain.aggregates.report_instance import ReportInstance
    from reporting.domain.aggregates.scheduled_report import ScheduledReport
    from reporting.domain.ports.i_analytics_kpi_query_port import IAnalyticsKPIQueryPort
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


def _instance_dto(instance: ReportInstance) -> ReportInstanceDTO:
    return ReportInstanceDTO(
        instance_id=str(instance.instance_id),
        tenant_id=str(instance.tenant_id),
        template_id=str(instance.template_id),
        report_type=instance.report_type.value,
        status=instance.status.value,
        trigger=instance.trigger.value,
        narrative=instance.narrative,
        narrative_variant=instance.narrative_variant,
        content=dict(instance.content),
        artifact_ref=instance.artifact_ref,
        error_reason=instance.error_reason,
        generated_by=instance.generated_by,
        created_at=instance.created_at.isoformat(),
        completed_at=instance.completed_at.isoformat() if instance.completed_at else None,
        schedule_id=str(instance.schedule_id) if instance.schedule_id else None,
    )


def _schedule_dto(schedule: ScheduledReport) -> ScheduledReportDTO:
    return ScheduledReportDTO(
        schedule_id=str(schedule.schedule_id),
        tenant_id=str(schedule.tenant_id),
        template_id=str(schedule.template_id),
        schedule=schedule.schedule_cron,
        cadence_minutes=schedule.cadence_minutes,
        status=schedule.status.value,
        next_run_at=schedule.next_run_at.isoformat(),
        last_run_at=schedule.last_run_at.isoformat() if schedule.last_run_at else None,
        parameters=dict(schedule.parameters),
        recipients=list(schedule.recipients),
        created_by=schedule.created_by,
        created_at=schedule.created_at.isoformat(),
    )


class ReportingApplicationService:
    def __init__(
        self,
        template_repo: IReportTemplateRepository,
        schedule_repo: IScheduledReportRepository,
        instance_repo: IReportInstanceRepository,
        kpi_port: IAnalyticsKPIQueryPort,
        ml_port: IMLSignalQueryPort,
        delivery_port: IReportDeliveryPort,
        event_publisher: IEventPublisher,
        *,
        bi_export_port: IBIExportPort | None = None,
        rate_limiter: BIExportRateLimiter | None = None,
        export_service: ReportExportService | None = None,
        generation_service: ReportGenerationService | None = None,
        schedule_service: ScheduledReportService | None = None,
    ) -> None:
        self._templates = template_repo
        self._schedules = schedule_repo
        self._instances = instance_repo
        self._kpis = kpi_port
        self._ml = ml_port
        self._delivery = delivery_port
        self._events = event_publisher
        self._bi_export = bi_export_port
        self._rate_limiter = rate_limiter or BIExportRateLimiter()
        self._export = export_service or ReportExportService()
        self._generation = generation_service or ReportGenerationService()
        self._schedule_svc = schedule_service or ScheduledReportService()

    async def create_scheduled_report(
        self, cmd: CreateScheduledReportCommand
    ) -> ScheduledReportDTO:
        require_at_least(cmd.actor_roles, AnalyticsRole.ANALYST)
        tenant = TenantId(cmd.tenant_id)
        template_id = ReportTemplateId(cmd.template_id)
        template = await self._templates.find_by_id(template_id)
        if template is None:
            raise ApplicationNotFoundError(str(cmd.template_id))
        now = datetime.now(UTC)
        try:
            schedule = self._schedule_svc.create(
                tenant_id=tenant,
                template_id=template_id,
                schedule_cron=cmd.schedule,
                cadence_minutes=max(1, cmd.cadence_minutes),
                next_run_at=now,
                parameters=dict(cmd.parameters),
                recipients=list(cmd.recipients),
                created_by=cmd.created_by,
                created_at=now,
            )
        except ReportingDomainError as exc:
            raise ApplicationValidationError(str(exc)) from exc
        await self._schedules.save(tenant, schedule)
        await self._events.publish_batch(schedule.pop_events())
        return _schedule_dto(schedule)

    async def generate_on_demand(self, cmd: GenerateReportOnDemandCommand) -> ReportInstanceDTO:
        require_at_least(cmd.actor_roles, AnalyticsRole.ANALYST)
        tenant = TenantId(cmd.tenant_id)
        template = await self._templates.find_by_id(ReportTemplateId(cmd.template_id))
        if template is None:
            raise ApplicationNotFoundError(str(cmd.template_id))
        now = datetime.now(UTC)
        bundle = await self._kpis.load_kpi_bundle(cmd.tenant_id)
        ml_bundle = await self._ml.load_active_signals(cmd.tenant_id)
        recipients = (
            list(cmd.parameters.get("recipients", []))
            if isinstance(cmd.parameters.get("recipients"), list)
            else []
        )
        try:
            instance = self._generation.build_instance(
                tenant_id=tenant,
                template=template,
                bundle=bundle,
                trigger=ReportTrigger.ON_DEMAND,
                generated_by=cmd.generated_by,
                at=now,
                parameters={
                    **dict(cmd.parameters),
                    "ml_signal_count": len(ml_bundle.signals),
                },
                ml_bundle=ml_bundle,
            )
        except ReportingDomainError as exc:
            raise ApplicationValidationError(str(exc)) from exc
        await self._instances.save(tenant, instance)
        await self._events.publish_batch(instance.pop_events())
        if instance.artifact_ref:
            await self._delivery.deliver(
                cmd.tenant_id,
                instance.instance_id.value,
                [str(r) for r in recipients],
                instance.artifact_ref,
            )
        return _instance_dto(instance)

    async def get_instance(
        self, tenant_id: UUID, instance_id: UUID, actor_roles: tuple[str, ...]
    ) -> ReportInstanceDTO:
        require_at_least(actor_roles, AnalyticsRole.VIEWER)
        instance = await self._instances.find_by_id(
            TenantId(tenant_id), ReportInstanceId(instance_id)
        )
        if instance is None:
            raise ApplicationNotFoundError(str(instance_id))
        return _instance_dto(instance)

    async def list_instances(
        self,
        tenant_id: UUID,
        actor_roles: tuple[str, ...],
        *,
        template_id: UUID | None = None,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> list[ReportInstanceDTO]:
        require_at_least(actor_roles, AnalyticsRole.VIEWER)
        tid = TenantId(tenant_id)
        rows = await self._instances.list_by_tenant(
            tid,
            template_id=ReportTemplateId(template_id) if template_id else None,
            from_dt=from_dt,
            to_dt=to_dt,
        )
        return [_instance_dto(r) for r in rows]

    async def generate_for_schedule(
        self, schedule: ScheduledReport, *, now: datetime | None = None
    ) -> ReportInstanceDTO | None:
        """Worker path — no RBAC; idempotent via claim_run."""
        at = now or datetime.now(UTC)
        tenant = schedule.tenant_id
        claimed = self._schedule_svc.claim_due_run(schedule, tenant, at)
        if not claimed:
            return None
        await self._schedules.save(tenant, schedule)
        template = await self._templates.find_by_id(schedule.template_id)
        if template is None:
            schedule.mark_error(tenant)
            await self._schedules.save(tenant, schedule)
            raise ApplicationNotFoundError(str(schedule.template_id))
        bundle = await self._kpis.load_kpi_bundle(tenant.value)
        ml_bundle = await self._ml.load_active_signals(tenant.value)
        try:
            instance = self._generation.build_instance(
                tenant_id=tenant,
                template=template,
                bundle=bundle,
                trigger=ReportTrigger.SCHEDULED,
                generated_by="scheduler",
                at=at,
                schedule_id=schedule.schedule_id,
                parameters=dict(schedule.parameters),
                ml_bundle=ml_bundle,
            )
        except ReportingDomainError as exc:
            schedule.mark_error(tenant)
            await self._schedules.save(tenant, schedule)
            raise ApplicationValidationError(str(exc)) from exc
        await self._instances.save(tenant, instance)
        await self._events.publish_batch(instance.pop_events())
        if instance.artifact_ref and schedule.recipients:
            await self._delivery.deliver(
                tenant.value,
                instance.instance_id.value,
                list(schedule.recipients),
                instance.artifact_ref,
            )
        return _instance_dto(instance)

    async def process_due_schedules(self, now: datetime | None = None) -> int:
        at = now or datetime.now(UTC)
        due = await self._schedules.find_due(at)
        processed = 0
        for schedule in due:
            result = await self.generate_for_schedule(schedule, now=at)
            if result is not None:
                processed += 1
        return processed

    async def export_instance(
        self,
        tenant_id: UUID,
        instance_id: UUID,
        fmt: str,
        actor_roles: tuple[str, ...],
        *,
        actor: str = "api",
    ) -> dict[str, object]:
        require_at_least(actor_roles, AnalyticsRole.ANALYST)
        try:
            report_fmt = ReportFormat(fmt)
        except ValueError as exc:
            raise ApplicationValidationError(str(exc)) from exc
        decision = self._rate_limiter.check(
            tenant_id,
            actor=actor,
            export_format=report_fmt.value,
            dataset_or_instance_ref=str(instance_id),
        )
        if not decision.allowed:
            raise ApplicationRateLimitedError(
                "BI/export rate limit exceeded",
                retry_after_seconds=decision.retry_after_seconds,
            )
        instance = await self._instances.find_by_id(
            TenantId(tenant_id), ReportInstanceId(instance_id)
        )
        if instance is None:
            raise ApplicationNotFoundError(str(instance_id))
        payload, content_type = self._export.export(
            dict(instance.content),
            fmt=report_fmt,
            narrative=instance.narrative,
        )
        return {
            "instance_id": str(instance_id),
            "format": report_fmt.value,
            "content_type": content_type,
            "bytes": payload,
            "byte_size": len(payload),
            "request_count_in_window": decision.request_count_in_window,
        }

    async def bi_export_page(
        self,
        tenant_id: UUID,
        dataset_ref: str,
        actor_roles: tuple[str, ...],
        *,
        page: int = 1,
        page_size: int = 100,
        actor: str = "bi",
    ) -> dict[str, object]:
        require_at_least(actor_roles, AnalyticsRole.ANALYST)
        if self._bi_export is None:
            raise ApplicationValidationError("BI export port not configured")
        decision = self._rate_limiter.check(
            tenant_id,
            actor=actor,
            export_format=ReportFormat.BI_CONNECTOR.value,
            dataset_or_instance_ref=dataset_ref,
        )
        if not decision.allowed:
            raise ApplicationRateLimitedError(
                "BI export rate limit exceeded",
                retry_after_seconds=decision.retry_after_seconds,
            )
        page_result = await self._bi_export.export_page(
            BIExportRequest(
                tenant_id=tenant_id,
                dataset_ref=dataset_ref,
                page=page,
                page_size=page_size,
                actor=actor,
            )
        )
        return {
            "dataset_ref": dataset_ref,
            "page": page_result.page,
            "page_size": page_result.page_size,
            "total_rows": page_result.total_rows,
            "has_more": page_result.has_more,
            "rows": page_result.rows,
            "request_count_in_window": decision.request_count_in_window,
        }
