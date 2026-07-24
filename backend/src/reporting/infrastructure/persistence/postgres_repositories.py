"""PostgreSQL repositories for reporting.

Session-per-call from an injected async_sessionmaker, matching the pattern
used across the other converted bounded contexts.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from reporting.domain.aggregates.report_instance import ReportInstance
from reporting.domain.aggregates.report_template import ReportTemplate
from reporting.domain.aggregates.scheduled_report import ScheduledReport
from reporting.domain.repositories.i_report_instance_repository import (
    IReportInstanceRepository,
)
from reporting.domain.repositories.i_report_template_repository import (
    IReportTemplateRepository,
)
from reporting.domain.repositories.i_scheduled_report_repository import (
    IScheduledReportRepository,
)
from reporting.domain.value_objects.enums import (
    ReportStatus,
    ReportTrigger,
    ReportType,
    ScheduleStatus,
)
from reporting.domain.value_objects.identifiers import (
    ReportInstanceId,
    ReportTemplateId,
    ScheduledReportId,
    TenantId,
)
from reporting.infrastructure.persistence.models.orm_models import (
    ReportInstanceModel,
    ReportTemplateModel,
    ScheduledReportModel,
)

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

_CADENCE_KEY = "_cadence_minutes"
_CREATED_BY_KEY = "_created_by"


# ── ReportTemplate ──────────────────────────────────────────────────────────


def _template_to_row(template: ReportTemplate) -> ReportTemplateModel:
    return ReportTemplateModel(
        id=template.template_id.value,
        tenant_id=template.tenant_id.value if template.tenant_id else None,
        report_type=template.report_type.value,
        name=template.name,
        sections_json=list(template.sections),
        version=template.version,
        is_platform=template.tenant_id is None,
        created_at=template.created_at,
    )


def _row_to_template(row: ReportTemplateModel) -> ReportTemplate:
    return ReportTemplate(
        template_id=ReportTemplateId(row.id),
        report_type=ReportType(row.report_type),
        name=row.name,
        sections=list(row.sections_json),
        version=row.version,
        created_at=row.created_at,
        tenant_id=TenantId.from_uuid(row.tenant_id) if row.tenant_id else None,
    )


class PgReportTemplateRepository(IReportTemplateRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def find_by_id(self, template_id: ReportTemplateId) -> ReportTemplate | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(ReportTemplateModel).where(ReportTemplateModel.id == template_id.value)
                )
            ).scalar_one_or_none()
            return _row_to_template(row) if row is not None else None

    async def find_by_type_for_tenant(
        self, tenant_id: TenantId, report_type: ReportType
    ) -> ReportTemplate | None:
        # Platform templates are tenant-unscoped in Phase 2 (in-memory repo
        # ignores tenant_id too — matched here for parity). report_type has
        # no uniqueness constraint in the migration, so this can't assume
        # at most one row; take the most recently created if several exist.
        del tenant_id
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(ReportTemplateModel)
                    .where(ReportTemplateModel.report_type == report_type.value)
                    .order_by(ReportTemplateModel.created_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            return _row_to_template(row) if row is not None else None

    async def save(self, template: ReportTemplate) -> None:
        async with self._session_factory() as session:
            await session.merge(_template_to_row(template))
            await session.commit()


# ── ScheduledReport ──────────────────────────────────────────────────────────


def _schedule_to_row(schedule: ScheduledReport) -> ScheduledReportModel:
    # cadence_minutes and created_by are domain state with no dedicated
    # migration column (schema has schedule_cron as the display string and
    # no created_by at all) — packed into parameters_json under reserved
    # keys rather than losing them silently.
    parameters = dict(schedule.parameters)
    parameters[_CADENCE_KEY] = schedule.cadence_minutes
    parameters[_CREATED_BY_KEY] = schedule.created_by
    return ScheduledReportModel(
        id=schedule.schedule_id.value,
        tenant_id=schedule.tenant_id.value,
        template_id=schedule.template_id.value,
        schedule_cron=schedule.schedule_cron,
        parameters_json=parameters,
        recipients_json=list(schedule.recipients),
        status=schedule.status.value,
        next_run_at=schedule.next_run_at,
        last_run_at=schedule.last_run_at,
        created_at=schedule.created_at,
    )


def _row_to_schedule(row: ScheduledReportModel) -> ScheduledReport:
    parameters = dict(row.parameters_json or {})
    cadence_minutes = int(parameters.pop(_CADENCE_KEY, 60))
    created_by = str(parameters.pop(_CREATED_BY_KEY, ""))
    # next_run_at is nullable in the migration but the aggregate always sets
    # it (ScheduledReport.create/claim_run never produce None) — a NULL row
    # here would mean the schedule was written by something other than this
    # aggregate.
    if row.next_run_at is None:
        raise ValueError(f"scheduled_reports row {row.id} has no next_run_at")
    return ScheduledReport(
        schedule_id=ScheduledReportId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        template_id=ReportTemplateId(row.template_id),
        schedule_cron=row.schedule_cron,
        cadence_minutes=cadence_minutes,
        next_run_at=row.next_run_at,
        status=ScheduleStatus(row.status),
        parameters=parameters,
        recipients=list(row.recipients_json or []),
        created_by=created_by,
        created_at=row.created_at,
        last_run_at=row.last_run_at,
    )


class PgScheduledReportRepository(IScheduledReportRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def find_by_id(
        self, tenant_id: TenantId, schedule_id: ScheduledReportId
    ) -> ScheduledReport | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(ScheduledReportModel).where(
                        ScheduledReportModel.tenant_id == tenant_id.value,
                        ScheduledReportModel.id == schedule_id.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_schedule(row) if row is not None else None

    async def find_due(self, now: datetime) -> list[ScheduledReport]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(ScheduledReportModel).where(
                        ScheduledReportModel.status == ScheduleStatus.ACTIVE.value,
                        ScheduledReportModel.next_run_at.is_not(None),
                        ScheduledReportModel.next_run_at <= now,
                    )
                )
            ).scalars().all()
            return [_row_to_schedule(r) for r in rows]

    async def save(self, tenant_id: TenantId, schedule: ScheduledReport) -> None:
        if schedule.tenant_id.value != tenant_id.value:
            raise ValueError("tenant mismatch on save")
        async with self._session_factory() as session:
            await session.merge(_schedule_to_row(schedule))
            await session.commit()

    async def list_by_tenant(self, tenant_id: TenantId) -> list[ScheduledReport]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(ScheduledReportModel).where(
                        ScheduledReportModel.tenant_id == tenant_id.value
                    )
                )
            ).scalars().all()
            return [_row_to_schedule(r) for r in rows]


# ── ReportInstance ───────────────────────────────────────────────────────────


def _instance_to_row(instance: ReportInstance) -> ReportInstanceModel:
    artifact: dict[str, Any] = {
        "content": dict(instance.content),
        "artifact_ref": instance.artifact_ref,
        "trigger": instance.trigger.value,
        "narrative_variant": instance.narrative_variant,
        "error_reason": instance.error_reason,
        "completed_at": instance.completed_at.isoformat() if instance.completed_at else None,
    }
    return ReportInstanceModel(
        id=instance.instance_id.value,
        tenant_id=instance.tenant_id.value,
        template_id=instance.template_id.value,
        scheduled_report_id=instance.schedule_id.value if instance.schedule_id else None,
        report_type=instance.report_type.value,
        status=instance.status.value,
        artifact_json=artifact,
        narrative=instance.narrative,
        generated_at=instance.created_at,
        generated_by=instance.generated_by,
    )


def _row_to_instance(row: ReportInstanceModel) -> ReportInstance:
    from datetime import datetime as _dt

    artifact = row.artifact_json or {}
    completed_at_raw = artifact.get("completed_at")
    return ReportInstance(
        instance_id=ReportInstanceId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        template_id=ReportTemplateId(row.template_id),
        report_type=ReportType(row.report_type),
        status=ReportStatus(row.status),
        trigger=ReportTrigger(artifact.get("trigger", ReportTrigger.ON_DEMAND.value)),
        generated_by=row.generated_by,
        created_at=row.generated_at,
        narrative=row.narrative,
        narrative_variant=artifact.get("narrative_variant", ""),
        content=dict(artifact.get("content") or {}),
        artifact_ref=artifact.get("artifact_ref"),
        error_reason=artifact.get("error_reason"),
        completed_at=_dt.fromisoformat(completed_at_raw) if completed_at_raw else None,
        schedule_id=(
            ScheduledReportId(row.scheduled_report_id) if row.scheduled_report_id else None
        ),
    )


class PgReportInstanceRepository(IReportInstanceRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def find_by_id(
        self, tenant_id: TenantId, instance_id: ReportInstanceId
    ) -> ReportInstance | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(ReportInstanceModel).where(
                        ReportInstanceModel.tenant_id == tenant_id.value,
                        ReportInstanceModel.id == instance_id.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_instance(row) if row is not None else None

    async def find_by_template(
        self,
        tenant_id: TenantId,
        template_id: ReportTemplateId,
        *,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> list[ReportInstance]:
        return await self.list_by_tenant(
            tenant_id, template_id=template_id, from_dt=from_dt, to_dt=to_dt
        )

    async def save(self, tenant_id: TenantId, instance: ReportInstance) -> None:
        if instance.tenant_id.value != tenant_id.value:
            raise ValueError("tenant mismatch on save")
        async with self._session_factory() as session:
            await session.merge(_instance_to_row(instance))
            await session.commit()

    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        template_id: ReportTemplateId | None = None,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> list[ReportInstance]:
        async with self._session_factory() as session:
            stmt = select(ReportInstanceModel).where(
                ReportInstanceModel.tenant_id == tenant_id.value
            )
            if template_id is not None:
                stmt = stmt.where(ReportInstanceModel.template_id == template_id.value)
            if from_dt is not None:
                stmt = stmt.where(ReportInstanceModel.generated_at >= from_dt)
            if to_dt is not None:
                stmt = stmt.where(ReportInstanceModel.generated_at <= to_dt)
            stmt = stmt.order_by(ReportInstanceModel.generated_at.desc())
            rows = (await session.execute(stmt)).scalars().all()
            return [_row_to_instance(r) for r in rows]
