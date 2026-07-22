from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from autonomous_intelligence.api.v1.routes import router
from autonomous_intelligence.infrastructure.container import AutonomousIntelligenceContainer


@pytest.mark.asyncio
async def test_create_and_queue() -> None:
    app = FastAPI()
    app.include_router(router)
    app.state.autonomous_intelligence_container = AutonomousIntelligenceContainer()
    headers = {"X-Tenant-Id": str(uuid4()), "X-Roles": "system,soc:detection_engineer"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/autonomous-intelligence/suggestions",
            json={
                "target_context": "detection",
                "target_type": "detection_rule_tuning",
                "confidence_score": 0.9,
                "rationale_summary": "raise threshold",
            },
            headers=headers,
        )
        assert r.status_code == 201
        q = await client.get("/autonomous-intelligence/suggestions", headers=headers)
        assert q.status_code == 200
        assert len(q.json()) == 1
