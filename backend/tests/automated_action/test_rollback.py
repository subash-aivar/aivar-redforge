from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from automated_action.application.commands.automation_commands import (
    RequestRollback,
    TriggerPlaybookExecution,
)
from automated_action.application.ports.lookups import PlaybookLookupView, PlaybookStepView
from automated_action.infrastructure.container import AutomatedActionContainer
from redforge.shared.identifiers import EntityId


@pytest.mark.asyncio
async def test_rollback() -> None:
    c = AutomatedActionContainer()
    tenant = EntityId.generate()
    pb = uuid4()
    c.playbook_lookup.put(
        PlaybookLookupView(
            str(pb),
            1,
            "h",
            "LOW",
            "APPROVED",
            [PlaybookStepView(1, "a", "EDR_CROWDSTRIKE", "host", {}, "LOW")],
        )
    )
    ex = await c.app.trigger(
        TriggerPlaybookExecution(
            tenant, pb, 1, "MANUAL", "manual", "e", "op", ("automation:operator",)
        )
    )
    await c.app.run_pending_step_loop(tenant, UUID(ex.execution_id))
    records = await c.app.action_records(tenant, UUID(ex.execution_id), ("playbook:analyst",))
    result = await c.app.request_rollback(
        RequestRollback(
            tenant, UUID(ex.execution_id), UUID(records[0].record_id), "cmd", ("soc:commander",)
        )
    )
    assert result["status"] == "COMPLETED"
