from __future__ import annotations

import pytest

from integration_hub.application.commands.connector_commands import RegisterConnector
from integration_hub.infrastructure.container import IntegrationHubContainer
from redforge.shared.identifiers import EntityId


@pytest.mark.asyncio
async def test_health_worker_ticks() -> None:
    c = IntegrationHubContainer()
    tenant = EntityId.generate()
    await c.app.register(
        RegisterConnector(
            tenant,
            "COMM_SLACK",
            "slack",
            "vault/slack",
            "API_KEY",
            "admin",
            ("integration:admin",),
        )
    )
    checked = await c.scheduler.tick(tenant)
    assert checked == 1
