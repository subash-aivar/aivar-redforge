from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from integration_hub.api.v1.routes import router
from integration_hub.infrastructure.container import IntegrationHubContainer


@pytest.mark.asyncio
async def test_register_list() -> None:
    app = FastAPI()
    app.include_router(router)
    app.state.integration_hub_container = IntegrationHubContainer()
    headers = {"X-Tenant-Id": str(uuid4()), "X-Roles": "integration:admin"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/integration-hub/connectors",
            json={
                "connector_type": "ITSM_JIRA",
                "display_name": "jira",
                "credential_vault_key": "v/jira",
                "credential_type": "API_KEY",
            },
            headers=headers,
        )
        assert r.status_code == 201
        lst = await client.get("/integration-hub/connectors", headers=headers)
        assert len(lst.json()) == 1
