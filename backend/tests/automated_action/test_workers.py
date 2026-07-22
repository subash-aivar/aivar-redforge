from __future__ import annotations

from uuid import uuid4

import pytest

from automated_action.application.commands.automation_commands import TriggerPlaybookExecution
from automated_action.application.ports.lookups import PlaybookLookupView, PlaybookStepView
from automated_action.infrastructure.container import AutomatedActionContainer


@pytest.mark.asyncio
async def test_scheduler_processes_pending() -> None:
    c = AutomatedActionContainer()
    tenant = uuid4()
    pb = uuid4()
    c.playbook_lookup.put(
        PlaybookLookupView(
            str(pb),
            1,
            "h",
            "LOW",
            "APPROVED",
            [PlaybookStepView(1, "a", "COMM_SLACK", "c", {}, "LOW")],
        )
    )
    await c.app.trigger(
        TriggerPlaybookExecution(
            tenant, pb, 1, "MANUAL", "manual", "e", "op", ("automation:operator",)
        )
    )
    result = await c.scheduler.tick_all(tenant)
    assert result["pending_processed"] == 1
