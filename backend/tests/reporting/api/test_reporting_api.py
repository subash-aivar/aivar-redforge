from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from reporting.api import dependencies as deps
from reporting.api.v1 import router
from reporting.domain.ports.i_analytics_kpi_query_port import KPISnapshotDTO
from reporting.domain.value_objects.enums import ReportType
from reporting.infrastructure.acl.analytics_kpi_query_adapter import (
    StaticAnalyticsKPIQueryAdapter,
)
from reporting.infrastructure.container import ReportingContainer


@pytest.fixture
def app() -> FastAPI:
    deps.reset_container()
    deps._container = ReportingContainer(
        kpi_port=StaticAnalyticsKPIQueryAdapter(
            kpis=(
                KPISnapshotDTO("MTTD", 55.0, "minutes", 3.0, "Active"),
                KPISnapshotDTO("CoveragePct", 80.0, "percent", 0.5, "Active"),
            )
        )
    )
    application = FastAPI()
    application.include_router(router, prefix="/api/v1")
    return application


def _headers(tenant: str, role: str) -> dict[str, str]:
    return {"X-Tenant-Id": tenant, "X-Analytics-Roles": role}


@pytest.mark.asyncio
async def test_reporting_api_flow(app: FastAPI) -> None:
    tenant = str(uuid4())
    container = await deps.get_container()
    template_id = container.template_id_for(ReportType.SECURITY_PROGRAM_DASHBOARD)
    assert template_id is not None

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        health = await client.get("/api/v1/reporting/health")
        assert health.status_code == 200
        assert health.json()["context"] == "reporting"
        assert health.json()["phase"] == 5

        templates = await client.get("/api/v1/reporting/templates")
        assert templates.status_code == 200
        assert len(templates.json()) == 7

        gen = await client.post(
            "/api/v1/reporting/reports",
            headers=_headers(tenant, "analytics:analyst"),
            json={
                "template_id": template_id,
                "generated_by": "analyst",
            },
        )
        assert gen.status_code == 200
        body = gen.json()
        assert body["status"] == "Complete"
        assert body["report_type"] == "SecurityProgramDashboard"
        assert body["narrative_variant"] == "MTTD Degradation"
        instance_id = body["instance_id"]

        got = await client.get(
            f"/api/v1/reporting/reports/{instance_id}",
            headers=_headers(tenant, "analytics:viewer"),
        )
        assert got.status_code == 200
        assert got.json()["instance_id"] == instance_id

        listed = await client.get(
            "/api/v1/reporting/reports",
            headers=_headers(tenant, "analytics:viewer"),
        )
        assert listed.status_code == 200
        assert len(listed.json()) == 1

        sched = await client.post(
            "/api/v1/reporting/schedules",
            headers=_headers(tenant, "analytics:analyst"),
            json={
                "template_id": template_id,
                "schedule": "0 * * * *",
                "cadence_minutes": 60,
                "created_by": "analyst",
                "recipients": ["ops@example.com"],
            },
        )
        assert sched.status_code == 200
        assert sched.json()["status"] == "Active"
        assert UUID(sched.json()["schedule_id"])

    deps.reset_container()


@pytest.mark.asyncio
async def test_viewer_forbidden_on_generate(app: FastAPI) -> None:
    tenant = str(uuid4())
    container = await deps.get_container()
    template_id = container.template_id_for(ReportType.KPI_TREND_REPORT)
    assert template_id is not None

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        gen = await client.post(
            "/api/v1/reporting/reports",
            headers=_headers(tenant, "analytics:viewer"),
            json={"template_id": template_id, "generated_by": "viewer"},
        )
        assert gen.status_code == 403

        sched = await client.post(
            "/api/v1/reporting/schedules",
            headers=_headers(tenant, "analytics:viewer"),
            json={
                "template_id": template_id,
                "schedule": "0 * * * *",
                "created_by": "viewer",
            },
        )
        assert sched.status_code == 403

    deps.reset_container()
