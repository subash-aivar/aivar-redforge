from __future__ import annotations

from uuid import uuid4

import pytest

from lessons_learned.domain.services.report_generation_service import (
    PostIncidentReportGenerationService,
)
from lessons_learned.domain.value_objects.enums import ReportFormat
from lessons_learned.infrastructure.container import LessonsLearnedContainer


@pytest.mark.asyncio
async def test_finalize_publishes_campaign_suggestion() -> None:
    c = LessonsLearnedContainer()
    tenant = uuid4()
    created = await c.app.create_for_incident(
        tenant, "inc-1", ("lessons_learned:contributor",), ["T1059"]
    )
    ll_id = __import__("uuid").UUID(created["ll_id"])
    await c.app.add_lesson(
        tenant, ll_id, "DETECTION_GAP", "missed alert", "high", ("lessons_learned:contributor",)
    )
    await c.app.review(tenant, ll_id, "approver", ("lessons_learned:approver",))
    result = await c.app.finalize(tenant, ll_id, "approver", ("lessons_learned:approver",))
    assert result["campaign_suggested"] is True
    assert len(c.bus.events) == 1


@pytest.mark.asyncio
async def test_no_campaign_without_techniques() -> None:
    c = LessonsLearnedContainer()
    tenant = uuid4()
    created = await c.app.create_for_incident(tenant, "inc-2", ("lessons_learned:contributor",), [])
    ll_id = __import__("uuid").UUID(created["ll_id"])
    result = await c.app.finalize(tenant, ll_id, "approver", ("lessons_learned:approver",))
    assert result["campaign_suggested"] is False
    assert c.bus.events == []


def test_four_formats() -> None:
    svc = PostIncidentReportGenerationService()
    for fmt in ReportFormat:
        payload = svc.generate(
            title="R",
            incident_id="i",
            lessons=[{"category": "OTHER", "description": "x"}],
            actions=[],
            fmt=fmt,
        )
        assert len(payload) > 0


@pytest.mark.asyncio
async def test_report_export_delivery() -> None:
    c = LessonsLearnedContainer()
    tenant = uuid4()
    created = await c.app.create_for_incident(
        tenant, "inc-3", ("lessons_learned:approver",), ["T1003"]
    )
    ll_id = __import__("uuid").UUID(created["ll_id"])
    report = await c.app.generate_report(tenant, ll_id, "PDF", ("lessons_learned:approver",))
    exported = await c.app.export_report(
        tenant,
        __import__("uuid").UUID(report["report_id"]),
        "ciso@example.com",
        ("lessons_learned:approver",),
    )
    assert exported["status"] == "EXPORTED"
    assert c.delivery.deliveries
