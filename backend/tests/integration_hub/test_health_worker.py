from __future__ import annotations

from uuid import uuid4

import pytest

from integration_hub.application.commands.connector_commands import RegisterConnector
from integration_hub.infrastructure.container import IntegrationHubContainer


@pytest.mark.asyncio
async def test_health_worker_ticks() -> None:
    c = IntegrationHubContainer()
    tenant = uuid4()
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
