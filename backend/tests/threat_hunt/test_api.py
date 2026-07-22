from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from threat_hunt.api.v1.routes import router
from threat_hunt.infrastructure.container import ThreatHuntContainer


@pytest.mark.asyncio
async def test_candidates_api() -> None:
    app = FastAPI()
    app.include_router(router)
    app.state.threat_hunt_container = ThreatHuntContainer()
    headers = {"X-Tenant-Id": str(uuid4()), "X-Roles": "system,soc:detection_engineer"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/threat-hunt/candidates",
            json={"anomaly_signal_ids": ["a1"], "technique_ids": ["T1059"]},
            headers=headers,
        )
        assert r.status_code == 201
        q = await client.get("/threat-hunt/candidates", headers=headers)
        assert len(q.json()) == 1
