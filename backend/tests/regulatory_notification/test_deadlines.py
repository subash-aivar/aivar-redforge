from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from regulatory_notification.application.exceptions import ApplicationForbiddenError
from regulatory_notification.domain.exceptions.domain_exceptions import DomainInvariantViolation
from regulatory_notification.domain.services.deadline_computation_service import (
    RegulatoryDeadlineComputationService,
)
from regulatory_notification.domain.value_objects.enums import RegulatoryRegime
from regulatory_notification.infrastructure.container import RegulatoryNotificationContainer


def test_gdpr_72h() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    d = RegulatoryDeadlineComputationService().compute(RegulatoryRegime.GDPR_ART33, start)
    assert d.deadline_hours == 72
    assert d.deadline_at == start + timedelta(hours=72)


def test_nis2_two_regimes() -> None:
    svc = RegulatoryDeadlineComputationService()
    start = datetime.now(UTC)
    early = svc.compute(RegulatoryRegime.NIS2_EARLY_WARNING, start)
    note = svc.compute(RegulatoryRegime.NIS2_NOTIFICATION, start)
    assert early.deadline_hours == 24
    assert note.deadline_hours == 72


@pytest.mark.asyncio
async def test_human_submit_and_immutability() -> None:
    c = RegulatoryNotificationContainer()
    tenant = uuid4()
    created = await c.app.start_clocks(tenant, str(uuid4()), ["GDPR_ART33"], ("incident:ciso",))
    nid = __import__("uuid").UUID(created[0]["notification_id"])
    await c.app.create_draft(tenant, nid, "draft", "officer", ("regulatory:officer",))
    await c.app.finalize_draft(tenant, nid, "legal", ("regulatory:legal",))
    await c.app.submit(
        tenant, nid, "legal", "GDPR_portal_submission", "REF-1", ("regulatory:legal",)
    )
    n = await c.notifications.find_by_id(
        __import__(
            "regulatory_notification.domain.value_objects.identifiers", fromlist=["TenantId"]
        ).TenantId(tenant),
        __import__(
            "regulatory_notification.domain.value_objects.identifiers",
            fromlist=["RegNotificationId"],
        ).RegNotificationId(nid),
    )
    assert n is not None and n.submission_record is not None
    with pytest.raises(DomainInvariantViolation):
        n.submit(
            __import__(
                "regulatory_notification.domain.value_objects.identifiers", fromlist=["TenantId"]
            ).TenantId(tenant),
            "x",
            "m",
            "r2",
            datetime.now(UTC),
        )


@pytest.mark.asyncio
async def test_analyst_cannot_submit() -> None:
    c = RegulatoryNotificationContainer()
    tenant = uuid4()
    created = await c.app.start_clocks(tenant, str(uuid4()), ["GDPR_ART33"], ("incident:ciso",))
    nid = __import__("uuid").UUID(created[0]["notification_id"])
    with pytest.raises(ApplicationForbiddenError):
        await c.app.submit(tenant, nid, "a", "m", "r", ("incident:analyst",))


@pytest.mark.asyncio
async def test_reconstitute_worker() -> None:
    c = RegulatoryNotificationContainer()
    tenant = uuid4()
    await c.app.start_clocks(tenant, str(uuid4()), ["GDPR_ART33"], ("incident:ciso",))
    result = await c.deadline_worker.reconstitute_and_tick()
    assert result["reconstituted"] is True
