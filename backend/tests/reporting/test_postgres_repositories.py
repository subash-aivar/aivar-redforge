"""Integration tests for reporting's Postgres repositories."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid7

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from reporting.domain.aggregates.report_instance import ReportInstance
from reporting.domain.aggregates.report_template import ReportTemplate
from reporting.domain.aggregates.scheduled_report import ScheduledReport
from reporting.domain.value_objects.enums import ReportTrigger, ReportType
from reporting.domain.value_objects.identifiers import (
    ReportInstanceId,
    ReportTemplateId,
    ScheduledReportId,
    TenantId,
)
from reporting.infrastructure.persistence.postgres_repositories import (
    PgReportInstanceRepository,
    PgReportTemplateRepository,
    PgScheduledReportRepository,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"), reason="requires TEST_DATABASE_URL"
    ),
]

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)


@pytest.fixture
def session_factory() -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.mark.asyncio
async def test_template_save_find_by_id_and_type(session_factory) -> None:
    repo = PgReportTemplateRepository(session_factory)
    now = datetime.now(UTC)

    template = ReportTemplate.create_platform(
        ReportTemplateId.generate(),
        ReportType.KPI_TREND_REPORT,
        "KPI Trend Report",
        ["trend_charts", "deltas"],
        now,
    )
    await repo.save(template)

    by_id = await repo.find_by_id(template.template_id)
    assert by_id is not None
    assert by_id.name == "KPI Trend Report"

    by_type = await repo.find_by_type_for_tenant(TenantId(uuid7()), ReportType.KPI_TREND_REPORT)
    assert by_type is not None
    assert str(by_type.template_id) == str(template.template_id)


@pytest.mark.asyncio
async def test_scheduled_report_round_trip_and_find_due(session_factory) -> None:
    repo = PgScheduledReportRepository(session_factory)
    tenant_id = TenantId(uuid7())
    template_id = ReportTemplateId.generate()
    now = datetime.now(UTC)

    schedule = ScheduledReport.create(
        ScheduledReportId.generate(),
        tenant_id,
        template_id,
        "0 9 * * MON",
        1440,
        now - timedelta(minutes=1),
        {"format": "PDF"},
        ["ciso@example.com"],
        "analyst-1",
        now,
    )
    await repo.save(tenant_id, schedule)

    fetched = await repo.find_by_id(tenant_id, schedule.schedule_id)
    assert fetched is not None
    assert fetched.cadence_minutes == 1440
    assert fetched.created_by == "analyst-1"
    assert fetched.parameters == {"format": "PDF"}
    assert fetched.recipients == ["ciso@example.com"]

    due = await repo.find_due(now)
    assert any(str(s.schedule_id) == str(schedule.schedule_id) for s in due)

    schedule.claim_run(tenant_id, now)
    await repo.save(tenant_id, schedule)

    still_due = await repo.find_due(now)
    assert not any(str(s.schedule_id) == str(schedule.schedule_id) for s in still_due)

    listed = await repo.list_by_tenant(tenant_id)
    assert len(listed) == 1


@pytest.mark.asyncio
async def test_report_instance_lifecycle_and_query(session_factory) -> None:
    repo = PgReportInstanceRepository(session_factory)
    tenant_id = TenantId(uuid7())
    template_id = ReportTemplateId.generate()
    now = datetime.now(UTC)

    instance = ReportInstance.start(
        ReportInstanceId.generate(),
        tenant_id,
        template_id,
        ReportType.EXECUTIVE_SECURITY_REPORT,
        ReportTrigger.ON_DEMAND,
        "analyst-1",
        now,
    )
    await repo.save(tenant_id, instance)

    instance.complete(
        tenant_id,
        narrative="Program stable this period",
        narrative_variant="General Program Pattern",
        content={"mttd_trend": [1, 2, 3]},
        artifact_ref="s3://bucket/report.pdf",
        at=now,
    )
    await repo.save(tenant_id, instance)

    fetched = await repo.find_by_id(tenant_id, instance.instance_id)
    assert fetched is not None
    assert fetched.status.value == "Complete"
    assert fetched.artifact_ref == "s3://bucket/report.pdf"
    assert fetched.content == {"mttd_trend": [1, 2, 3]}
    assert fetched.narrative_variant == "General Program Pattern"
    assert fetched.completed_at is not None

    by_template = await repo.find_by_template(tenant_id, template_id)
    assert len(by_template) == 1

    listed = await repo.list_by_tenant(tenant_id)
    assert len(listed) == 1
