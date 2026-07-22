"""Integration tests for lessons_learned's Postgres repositories."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid7

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from lessons_learned.domain.aggregates.lessons_learned import LessonsLearned
from lessons_learned.domain.aggregates.post_incident_report import PostIncidentReport
from lessons_learned.domain.value_objects.enums import (
    ActionItemPriority,
    ActionItemStatus,
    LessonCategory,
    PostIncidentReportStatus,
    ReportFormat,
)
from lessons_learned.domain.value_objects.identifiers import (
    LessonsLearnedId,
    PostIncidentReportId,
    TenantId,
)
from lessons_learned.infrastructure.persistence.postgres_repositories import (
    PgLessonsLearnedRepository,
    PgPostIncidentReportRepository,
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
async def test_lessons_learned_full_round_trip(session_factory) -> None:
    repo = PgLessonsLearnedRepository(session_factory)
    tenant_id = TenantId(uuid7())
    incident_id = str(uuid7())
    now = datetime.now(UTC)

    ll = LessonsLearned.create(LessonsLearnedId.generate(), tenant_id, incident_id, now)
    ll.add_lesson(tenant_id, LessonCategory.DETECTION_GAP, "No alert fired", "delayed response")
    action_id = ll.add_action(
        tenant_id, "Tune detection rule", "raise sensitivity", "analyst-1",
        ActionItemPriority.P2_HIGH, None,
    )
    ll.confirmed_technique_ids.append("T1059")
    await repo.save(tenant_id, ll)

    fetched = await repo.find_by_id(tenant_id, ll.ll_id)
    assert fetched is not None
    assert len(fetched.lessons) == 1
    assert fetched.lessons[0].category == LessonCategory.DETECTION_GAP
    assert len(fetched.action_items) == 1
    assert fetched.action_items[0].action_id == action_id
    assert fetched.confirmed_technique_ids == ["T1059"]

    by_incident = await repo.find_by_incident(tenant_id, incident_id)
    assert by_incident is not None
    assert str(by_incident.ll_id) == str(ll.ll_id)

    fetched.update_action_status(tenant_id, action_id, ActionItemStatus.COMPLETED, "done")
    fetched.review(tenant_id, "lead-1", now)
    fetched.finalize(tenant_id, "manager-1", now)
    await repo.save(tenant_id, fetched)

    final = await repo.find_by_id(tenant_id, ll.ll_id)
    assert final is not None
    assert final.status.value == "FINALIZED"
    assert final.action_items[0].status == ActionItemStatus.COMPLETED
    assert final.campaign_retargeting_suggestion_ref is not None


@pytest.mark.asyncio
async def test_post_incident_report_lifecycle(session_factory) -> None:
    repo = PgPostIncidentReportRepository(session_factory)
    tenant_id = TenantId(uuid7())
    incident_id = str(uuid7())
    now = datetime.now(UTC)

    report = PostIncidentReport(
        PostIncidentReportId.generate(),
        tenant_id,
        incident_id,
        LessonsLearnedId.generate(),
        ReportFormat.PDF,
        PostIncidentReportStatus.GENERATING,
    )
    await repo.save(tenant_id, report)

    report.complete(tenant_id, "s3://bucket/report.pdf", b"%PDF-1.4 fake report bytes", now)
    await repo.save(tenant_id, report)

    fetched = await repo.find_by_id(tenant_id, report.report_id)
    assert fetched is not None
    assert fetched.status.value == "COMPLETE"
    assert fetched.artifact_bytes == b"%PDF-1.4 fake report bytes"
    assert fetched.artifact_ref == "s3://bucket/report.pdf"

    fetched.export(tenant_id, "email:ciso@example.com", now)
    await repo.save(tenant_id, fetched)

    by_incident = await repo.find_by_incident(tenant_id, incident_id)
    assert len(by_incident) == 1
    assert by_incident[0].status.value == "EXPORTED"
