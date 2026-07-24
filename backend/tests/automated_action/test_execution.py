from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from automated_action.application.commands.automation_commands import TriggerPlaybookExecution
from automated_action.application.ports.lookups import (
    PlaybookLookupView,
    PlaybookStepView,
    PolicyLookupView,
)
from automated_action.domain.exceptions.domain_exceptions import KillSwitchActive
from automated_action.domain.services.execution_policy_service import (
    ExecutionPolicyService,
    PolicySnapshot,
)
from automated_action.infrastructure.container import AutomatedActionContainer
from redforge.shared.identifiers import EntityId


@pytest.mark.asyncio
async def test_full_pipeline() -> None:
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
            [
                PlaybookStepView(1, "a", "COMM_SLACK", "c", {}, "LOW"),
                PlaybookStepView(2, "b", "ITSM_JIRA", "c", {}, "LOW"),
            ],
        )
    )
    ex = await c.app.trigger(
        TriggerPlaybookExecution(
            tenant, pb, 1, "MANUAL", "manual", "evt", "op", ("automation:operator",)
        )
    )
    done = await c.app.run_pending_step_loop(tenant, UUID(ex.execution_id))
    assert done.status == "COMPLETED"
    assert done.current_step == 2


def test_policy_kill_switch() -> None:
    with pytest.raises(KillSwitchActive):
        ExecutionPolicyService().evaluate(
            PolicySnapshot(True, 5, 100), running_count=0, actions_last_hour=0
        )


@pytest.mark.asyncio
async def test_kill_switch_halts_execution() -> None:
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
            [PlaybookStepView(1, "a", "COMM_SLACK", "c", {}, "LOW")],
        )
    )
    c.playbook_lookup.put_policy(str(tenant), PolicyLookupView(True, 5, 100))
    with pytest.raises(KillSwitchActive):
        await c.app.trigger(
            TriggerPlaybookExecution(
                tenant, pb, 1, "MANUAL", "manual", "evt", "op", ("automation:operator",)
            )
        )
