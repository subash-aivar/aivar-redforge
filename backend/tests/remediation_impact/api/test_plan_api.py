from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from remediation_impact.api import dependencies as deps
from remediation_impact.api.v1 import router
from remediation_impact.infrastructure.acl.exposure_score_query_adapter import (
    StaticExposureScoreQueryAdapter,
)
from remediation_impact.infrastructure.container import RemediationImpactContainer


@pytest.fixture
def app() -> FastAPI:
    deps.reset_container()
    deps._container = RemediationImpactContainer(
        score_port=StaticExposureScoreQueryAdapter({"a1": 5.0}, version=1)
    )
    application = FastAPI()
    application.include_router(router, prefix="/api/v1")
    return application


@pytest.mark.asyncio
async def test_plan_api_flow(app: FastAPI) -> None:
    tenant = str(uuid4())
    headers = {"X-Tenant-Id": tenant, "X-Exposure-Roles": "exposure:analyst"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        gen = await client.post(
            "/api/v1/remediation-impact/plans",
            headers=headers,
            json={
                "candidate_remediations": [
                    {
                        "remediation_id": "r1",
                        "affected_asset_refs": ["a1"],
                        "estimated_base_reduction": 1.5,
                    }
                ],
                "plan_budget": 1,
            },
        )
        assert gen.status_code == 200
        plan_id = gen.json()["plan_id"]
        got = await client.get(
            f"/api/v1/remediation-impact/plans/{plan_id}",
            headers={**headers, "X-Exposure-Roles": "exposure:simulation_reader"},
        )
        assert got.status_code == 200
        commit = await client.post(
            f"/api/v1/remediation-impact/plans/{plan_id}/commit",
            headers=headers,
            json={"committed_by": "ops"},
        )
        assert commit.status_code == 200
        assert commit.json()["status"] == "Committed"
    deps.reset_container()
