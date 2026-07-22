from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from playbook.api.v1.routes import router
from playbook.infrastructure.container import PlaybookContainer


@pytest.fixture
def app() -> FastAPI:
    application = FastAPI()
    application.include_router(router)
    application.state.playbook_container = PlaybookContainer()
    return application


@pytest.mark.asyncio
async def test_create_and_list(app: FastAPI) -> None:
    tenant = str(uuid4())
    headers = {
        "X-Tenant-Id": tenant,
        "X-Roles": "playbook:engineer,playbook:analyst",
    }
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/playbooks",
            json={"name": "n", "description": "d", "created_by": "e"},
            headers=headers,
        )
        assert r.status_code == 201
        lst = await client.get("/playbooks", headers=headers)
        assert lst.status_code == 200
        assert len(lst.json()) == 1
