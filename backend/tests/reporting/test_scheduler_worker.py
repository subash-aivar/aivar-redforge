"""Integration: ReportSchedulerWorker due schedules + idempotency."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from redforge.shared.identifiers import EntityId
from reporting.application.commands.reporting_commands import CreateScheduledReportCommand
from reporting.domain.value_objects.enums import ReportType
from reporting.domain.value_objects.identifiers import TenantId
from reporting.infrastructure.container import ReportingContainer
from reporting.infrastructure.workers.report_scheduler_worker import ReportSchedulerWorker


@pytest.mark.asyncio
async def test_scheduler_invokes_due_schedules_only() -> None:
    container = ReportingContainer()
    tenant = EntityId.generate()
    template_id = container.template_id_for(ReportType.EXECUTIVE_SECURITY_REPORT)
    assert template_id is not None

    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    await container.app.create_scheduled_report(
        CreateScheduledReportCommand(
            tenant_id=tenant,
            template_id=UUID(template_id),
            schedule="0 * * * *",
            created_by="tester",
            cadence_minutes=60,
            actor_roles=("analytics:analyst",),
        )
    )
    schedules = await container.schedule_repo.list_by_tenant(TenantId(tenant))
    assert len(schedules) == 1
    schedules[0].next_run_at = now + timedelta(hours=2)

    worker = ReportSchedulerWorker(container.app)
    processed = await worker.tick(now)
    assert processed == 0

    schedules[0].next_run_at = now - timedelta(minutes=1)
    processed = await worker.tick(now)
    assert processed == 1

    instances = await container.instance_repo.list_by_tenant(TenantId(tenant))
    assert len(instances) == 1
    assert instances[0].trigger.value == "Scheduled"


@pytest.mark.asyncio
async def test_scheduler_idempotent_no_double_fire() -> None:
    container = ReportingContainer()
    tenant = EntityId.generate()
    template_id = container.template_id_for(ReportType.ANOMALY_SUMMARY_REPORT)
    assert template_id is not None

    await container.app.create_scheduled_report(
        CreateScheduledReportCommand(
            tenant_id=tenant,
            template_id=UUID(template_id),
            schedule="*/5 * * * *",
            created_by="tester",
            cadence_minutes=5,
            actor_roles=("analytics:admin",),
        )
    )
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    schedules = await container.schedule_repo.list_by_tenant(TenantId(tenant))
    schedules[0].next_run_at = now

    worker = container.scheduler_worker
    first = await worker.tick(now)
    second = await worker.tick(now)
    assert first == 1
    assert second == 0

    instances = await container.instance_repo.list_by_tenant(TenantId(tenant))
    assert len(instances) == 1
