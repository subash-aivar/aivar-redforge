from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from automated_action.api.v1.routes import router
from automated_action.application.ports.lookups import PlaybookLookupView, PlaybookStepView
from automated_action.infrastructure.container import AutomatedActionContainer


@pytest.mark.asyncio
async def test_trigger_api() -> None:
    app = FastAPI()
    app.include_router(router)
    c = AutomatedActionContainer()
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
    app.state.automated_action_container = c
    headers = {"X-Tenant-Id": str(uuid4()), "X-Roles": "automation:operator"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/executions",
            json={
                "playbook_id": str(pb),
                "version_number": 1,
                "source_event_id": "e1",
            },
            headers=headers,
        )
        assert r.status_code == 201
