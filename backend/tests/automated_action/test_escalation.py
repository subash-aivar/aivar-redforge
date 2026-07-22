from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from automated_action.application.commands.automation_commands import (
    AuthorizeAutomationStep,
    TriggerPlaybookExecution,
)
from automated_action.application.ports.lookups import PlaybookLookupView, PlaybookStepView
from automated_action.domain.exceptions.domain_exceptions import SeparationOfDutiesViolation
from automated_action.infrastructure.container import AutomatedActionContainer


@pytest.mark.asyncio
async def test_escalation_pause_resume_and_sod() -> None:
    c = AutomatedActionContainer()
    tenant = uuid4()
    pb_id = uuid4()
    c.playbook_lookup.put(
        PlaybookLookupView(
            str(pb_id),
            1,
            "h",
            "HIGH",
            "APPROVED",
            [PlaybookStepView(1, "quarantine", "EDR_CROWDSTRIKE", "host", {}, "HIGH")],
        )
    )
    ex = await c.app.trigger(
        TriggerPlaybookExecution(
            tenant, pb_id, 1, "MANUAL", "manual", "e1", "op1", ("automation:operator",)
        )
    )
    paused = await c.app.run_pending_step_loop(tenant, UUID(ex.execution_id))
    assert paused.status == "AWAITING_AUTHORIZATION"
    loaded = await c.executions.get(
        __import__(
            "automated_action.domain.value_objects.identifiers", fromlist=["AutomationExecutionId"]
        ).AutomationExecutionId(UUID(ex.execution_id)),
        c.app._tenant(tenant),
    )
    assert loaded and loaded.escalation_request
    with pytest.raises(SeparationOfDutiesViolation):
        await c.app.authorize_step(
            AuthorizeAutomationStep(
                tenant,
                UUID(ex.execution_id),
                loaded.escalation_request.escalation_id,
                "op1",
                ("soc:commander",),
                None,
                ("soc:commander",),
            )
        )
    done = await c.app.authorize_step(
        AuthorizeAutomationStep(
            tenant,
            UUID(ex.execution_id),
            loaded.escalation_request.escalation_id,
            "commander2",
            ("soc:commander",),
            "ok",
            ("soc:commander",),
        )
    )
    assert done.status == "COMPLETED"
