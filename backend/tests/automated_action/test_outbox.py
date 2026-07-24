from __future__ import annotations

from uuid import uuid4

import pytest

from automated_action.application.commands.automation_commands import TriggerPlaybookExecution
from automated_action.application.ports.lookups import PlaybookLookupView, PlaybookStepView
from automated_action.domain.value_objects.enums import ActionRecordStatus
from automated_action.infrastructure.container import AutomatedActionContainer
from redforge.shared.identifiers import EntityId


@pytest.mark.asyncio
async def test_outbox_pending_before_complete() -> None:
    c = AutomatedActionContainer()
    tenant = EntityId.generate()
    pb_id = uuid4()
    c.playbook_lookup.put(
        PlaybookLookupView(
            str(pb_id),
            1,
            "hash",
            "LOW",
            "APPROVED",
            [
                PlaybookStepView(1, "create_ticket", "ITSM_JIRA", "t", {}, "LOW"),
            ],
        )
    )
    ex = await c.app.trigger(
        TriggerPlaybookExecution(
            tenant, pb_id, 1, "MANUAL", "manual", "evt-1", "op1", ("automation:operator",)
        )
    )
    done = await c.app.run_pending_step_loop(tenant, __import__("uuid").UUID(ex.execution_id))
    assert done.status == "COMPLETED"
    records = await c.records.find_by_execution(
        c.app._tenant(tenant)
        and __import__(
            "automated_action.domain.value_objects.identifiers", fromlist=["AutomationExecutionId"]
        ).AutomationExecutionId(__import__("uuid").UUID(ex.execution_id)),
        c.app._tenant(tenant),
    )
    assert records
    assert records[0].status == ActionRecordStatus.COMPLETED
