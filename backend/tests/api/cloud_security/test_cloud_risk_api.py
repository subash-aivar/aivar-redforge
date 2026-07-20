"""API tests for M26 Phase 7 Cloud Risk endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from redforge.api.security import TenantContext, get_tenant_context
from redforge.api.v1.cloud_risk import router as cloud_risk_router
from redforge.application.cloud_security.risk.dtos import (
    RiskAssessmentResultDTO,
    RiskFactorDTO,
    RiskScoreDTO,
    RiskSummaryDTO,
)
from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware

ORG = "01HXORG0000000000000000001"
ASSET = uuid4()
RISK = uuid4()
NOW = datetime.now(UTC)


def _score_dto() -> RiskScoreDTO:
    return RiskScoreDTO(
        risk_id=str(RISK),
        organization_id=ORG,
        cloud_asset_id=str(ASSET),
        overall_score=6.5,
        threat_intel_score=0.0,
        compliance_score=1.0,
        identity_score=2.0,
        exposure_score=3.0,
        business_criticality_score=5.0,
        attack_path_score=0.0,
        cspm_score=4.0,
        kubernetes_score=0.0,
        runtime_score=1.0,
        confidence="MEDIUM",
        trend="STABLE",
        state="ACTIVE",
        calculation_version="1.0.0+default",
        computed_at=NOW,
        valid_until=NOW,
        score_components=[],
        evidence=[],
    )


class _FakeRiskService:
    async def calculate(self, command: Any) -> RiskAssessmentResultDTO:
        return RiskAssessmentResultDTO(
            assessment_id=str(uuid4()),
            organization_id=command.organization_id,
            scope="ASSET" if command.asset_id else "ORGANIZATION",
            target_id=str(command.asset_id or command.organization_id),
            status="COMPLETED",
            assets_evaluated=1,
            risks_created=1,
            risks_updated=0,
            calculation_version="1.0.0+default",
            diagnostics={"attack_path_stub": True},
        )

    async def recalculate_organization(self, organization_id: str) -> RiskAssessmentResultDTO:
        return await self.calculate(
            type("C", (), {"organization_id": organization_id, "asset_id": None})()
        )

    async def list_scores(self, organization_id: str, **kwargs: Any) -> list[RiskScoreDTO]:
        return [_score_dto()]

    async def get_score(self, organization_id: str, **kwargs: Any) -> RiskScoreDTO:
        return _score_dto()

    async def summary(self, organization_id: str) -> RiskSummaryDTO:
        return RiskSummaryDTO(
            organization_id=ORG,
            total_scores=1,
            average_score=6.5,
            critical_count=0,
            high_count=0,
            by_state={"ACTIVE": 1},
            by_trend={"STABLE": 1},
        )

    async def top(self, organization_id: str, **kwargs: Any) -> list[RiskScoreDTO]:
        return [_score_dto()]

    async def history(
        self, organization_id: str, asset_id: Any, **kwargs: Any
    ) -> list[dict[str, object]]:
        return [{"overall_score": 6.5, "cloud_asset_id": str(asset_id)}]

    async def list_factors(
        self, organization_id: str, asset_id: Any
    ) -> list[RiskFactorDTO]:
        return [
            RiskFactorDTO(
                factor_id=str(uuid4()),
                organization_id=ORG,
                cloud_asset_id=str(asset_id),
                category="CONFIGURATION",
                source="CSPM",
                title="cspm:4.00",
                description="open_findings=1",
                score=4.0,
                severity="MEDIUM",
                confidence="MEDIUM",
            )
        ]


@pytest.fixture
def app() -> FastAPI:
    application = FastAPI()
    application.add_middleware(ErrorHandlerMiddleware)
    application.include_router(cloud_risk_router, prefix="/api/v1")

    async def _tenant() -> TenantContext:
        return TenantContext(
            user_id="01HXUSER000000000000000001",
            email="owner@example.com",
            organization_id=ORG,
            role=MembershipRole.OWNER,
            permissions=frozenset(ROLE_PERMISSIONS[MembershipRole.OWNER]),
        )

    class _OrgStub:
        async def get_by_id(self, organization_id: str) -> object:
            class _Org:
                status = "active"

            return _Org()

    from redforge.api.dependencies import (
        get_organization_service,
        get_risk_calculation_service,
    )

    application.dependency_overrides[get_tenant_context] = _tenant
    application.dependency_overrides[get_risk_calculation_service] = lambda: _FakeRiskService()
    application.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    return application


@pytest.fixture
async def client(app: FastAPI) -> Any:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_calculate_risk(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/cloud-foundation/risk/calculate",
        json={"asset_id": str(ASSET)},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "COMPLETED"
    assert body["diagnostics"]["attack_path_stub"] is True


@pytest.mark.asyncio
async def test_recalculate_organization(client: AsyncClient) -> None:
    resp = await client.post("/api/v1/cloud-foundation/risk/recalculate-organization")
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_list_scores(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/cloud-foundation/risk/scores")
    assert resp.status_code == 200
    assert resp.json()[0]["attack_path_score"] == 0.0


@pytest.mark.asyncio
async def test_get_score(client: AsyncClient) -> None:
    resp = await client.get(f"/api/v1/cloud-foundation/risk/scores/{RISK}")
    assert resp.status_code == 200
    assert resp.json()["risk_id"] == str(RISK)


@pytest.mark.asyncio
async def test_get_by_asset(client: AsyncClient) -> None:
    resp = await client.get(f"/api/v1/cloud-foundation/risk/by-asset/{ASSET}")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_summary(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/cloud-foundation/risk/summary")
    assert resp.status_code == 200
    assert resp.json()["total_scores"] == 1


@pytest.mark.asyncio
async def test_history(client: AsyncClient) -> None:
    resp = await client.get(
        "/api/v1/cloud-foundation/risk/history",
        params={"asset_id": str(ASSET)},
    )
    assert resp.status_code == 200
    assert len(resp.json()) == 1


@pytest.mark.asyncio
async def test_top(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/cloud-foundation/risk/top", params={"limit": 5})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_factors(client: AsyncClient) -> None:
    resp = await client.get(
        "/api/v1/cloud-foundation/risk/factors",
        params={"asset_id": str(ASSET)},
    )
    assert resp.status_code == 200
    assert resp.json()[0]["source"] == "CSPM"
