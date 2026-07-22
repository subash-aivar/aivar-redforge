from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI, Header
from httpx import ASGITransport, AsyncClient

from exposure_reporting.api import dependencies as deps
from exposure_reporting.api.v1 import router
from exposure_reporting.infrastructure.acl.exposure_data_query_adapter import (
    StaticExposureDataQueryAdapter,
)
from exposure_reporting.infrastructure.container import ExposureReportingContainer
from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import MembershipRole, Permission


def _override_tenant_context(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
) -> TenantContext:
    """Test-only stand-in for JWT verification: mints a TenantContext for
    whatever X-Tenant-Id the test sends, since these tests exercise
    role-based authorization (X-Exposure-Roles) without a full login flow.
    """
    return TenantContext(
        user_id=str(uuid4()),
        email="exposure-test@example.com",
        organization_id=x_tenant_id,
        role=MembershipRole.OWNER,
        permissions=frozenset(Permission),
    )


@pytest.fixture
def app() -> FastAPI:
    deps.reset_container()
    deps._container = ExposureReportingContainer(
        exposure_port=StaticExposureDataQueryAdapter(
            asset_scores={"a1": 7.0},
            amplifier_weight_prevalence={"ThreatActorMatch": 4.0},
        )
    )
    application = FastAPI()
    application.include_router(router, prefix="/api/v1")
    application.dependency_overrides[get_tenant_context] = _override_tenant_context
    return application


@pytest.mark.asyncio
async def test_reporting_api_flow(app: FastAPI) -> None:
    tenant = str(uuid4())
    asset = str(uuid4())
    headers_eng = {
        "X-Tenant-Id": tenant,
        "X-Exposure-Roles": "exposure:engineer",
    }
    headers_analyst = {
        "X-Tenant-Id": tenant,
        "X-Exposure-Roles": "exposure:analyst",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        bim = await client.post(
            "/api/v1/exposure-reporting/business-impact-mappings",
            headers=headers_eng,
            json={
                "asset_ref_id": asset,
                "criticality": "High",
                "impact_domain": "Operations",
                "authored_by": "eng",
                "regulatory_scope": ["NIS2"],
            },
        )
        assert bim.status_code == 200
        gen = await client.post(
            "/api/v1/exposure-reporting/reports",
            headers=headers_analyst,
            json={
                "report_type": "BoardRiskSummary",
                "generated_by": "analyst",
            },
        )
        assert gen.status_code == 200
        report_id = gen.json()["report_id"]
        assert gen.json()["template_id"] == "Active Threat Actor Targeting"
        dash = await client.get(
            "/api/v1/exposure-reporting/dashboard",
            headers={"X-Tenant-Id": tenant, "X-Exposure-Roles": "exposure:viewer"},
        )
        assert dash.status_code == 200
        export = await client.get(
            f"/api/v1/exposure-reporting/reports/{report_id}/export",
            headers=headers_analyst,
            params={"format": "json"},
        )
        assert export.status_code == 200
        health = await client.get("/api/v1/exposure-reporting/health")
        assert health.status_code == 200
        assert health.json()["phase"] == 5
    deps.reset_container()
