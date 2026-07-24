from __future__ import annotations

from uuid import uuid4

import pytest

from playbook.application.commands.playbook_commands import ActivateKillSwitch, ResetKillSwitch
from playbook.application.exceptions import ApplicationForbiddenError
from playbook.domain.exceptions.domain_exceptions import KillSwitchActive
from playbook.infrastructure.container import PlaybookContainer
from redforge.shared.identifiers import EntityId


@pytest.mark.asyncio
async def test_kill_switch_activate_reset() -> None:
    c = PlaybookContainer()
    tenant = EntityId.generate()
    ciso = ("incident:ciso",)
    dto = await c.app.activate_kill_switch(ActivateKillSwitch(tenant, "ciso1", "emergency", ciso))
    assert dto.kill_switch_state == "TRIGGERED"
    policy = await c.policies.get_or_create_default(c.app._tenant(tenant))
    with pytest.raises(KillSwitchActive):
        policy.assert_armed()
    reset = await c.app.reset_kill_switch(ResetKillSwitch(tenant, "ciso1", ciso))
    assert reset.kill_switch_state == "ARMED"
    assert len(c.kill_switch_log) == 2


@pytest.mark.asyncio
async def test_kill_switch_requires_ciso() -> None:
    c = PlaybookContainer()
    with pytest.raises(ApplicationForbiddenError):
        await c.app.activate_kill_switch(ActivateKillSwitch(uuid4(), "x", "r", ("soc:commander",)))
