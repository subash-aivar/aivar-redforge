"""API tests for M26 Phase 8 Cloud Platform endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from redforge.api.dependencies import get_cloud_platform_service
from redforge.api.security import TenantContext, get_tenant_context
from redforge.api.v1.cloud_platform import router as cloud_platform_router
from redforge.application.cloud_security.platform.dtos import (
    OrchestrationRunDTO,
    OrchestrationRunPageDTO,
    PackageHealthDTO,
    PlatformDiagnosticsDTO,
    PlatformHealthDTO,
    PlatformSummaryDTO,
    StepResultDTO,
    SyncStatusDTO,
    ValidationCheckDTO,
    ValidationReportDTO,
)
from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware

ORG = "01HXORG0000000000000000001"
NOW = datetime.now(UTC)
ACCOUNT = uuid4()
RUN_ID = uuid4()


def _run_dto(**kwargs: Any) -> OrchestrationRunDTO:
    base = dict(
        run_id=str(RUN_ID),
        organization_id=ORG,
        scope="ACCOUNT",
        target_id=str(ACCOUNT),
        status="COMPLETED",
        steps=[
            StepResultDTO(
                step_name="DISCOVER_ASSETS",
                status="COMPLETED",
                started_at=NOW,
                completed_at=NOW,
                duration_ms=1.0,
                message="ok",
                error=None,
                details={},
            )
        ],
        diagnostics={},
        operation_id="op_api",
        correlation_id="",
        request_id="",
        started_at=NOW,
        completed_at=NOW,
        row_version=1,
    )
    base.update(kwargs)
    return OrchestrationRunDTO(**base)  # type: ignore[arg-type]


class _FakePlatformService:
    async def health(self) -> PlatformHealthDTO:
        return PlatformHealthDTO(
            overall="healthy",
            packages=[
                PackageHealthDTO(package="foundation", status="healthy", message="ok"),
                PackageHealthDTO(package="risk", status="healthy", message="ok"),
            ],
            checked_at=NOW,
            operation_id="op_h",
        )

    async def health_package(self, package: str) -> PackageHealthDTO:
        return PackageHealthDTO(package=package, status="healthy", message="ok")

    async def readiness(self, organization_id: str) -> PlatformHealthDTO:
        return await self.health()

    async def summary(self, organization_id: str) -> PlatformSummaryDTO:
        return PlatformSummaryDTO(
            organization_id=organization_id,
            account_count=1,
            provider_count=1,
            last_run_status="COMPLETED",
            last_run_id=str(RUN_ID),
            last_run_at=NOW,
            health_overall="healthy",
            validation_passed=True,
        )

    async def validate(self, organization_id: str, *, persist: bool = True) -> ValidationReportDTO:
        return ValidationReportDTO(
            organization_id=organization_id,
            overall_passed=True,
            checks=[
                ValidationCheckDTO(name="ontology_version", passed=True, message="12"),
                ValidationCheckDTO(name="migration_head", passed=True, message="0053"),
            ],
            created_at=NOW,
            operation_id="op_v",
        )

    async def last_validation_report(
        self, organization_id: str
    ) -> ValidationReportDTO | None:
        return await self.validate(organization_id)

    async def orchestrate(self, command: Any) -> OrchestrationRunDTO:
        return _run_dto(
            organization_id=command.organization_id,
            target_id=str(command.cloud_account_id or command.organization_id),
        )

    async def list_runs(
        self, organization_id: str, **kwargs: Any
    ) -> OrchestrationRunPageDTO:
        return OrchestrationRunPageDTO(
            items=[_run_dto()], page=1, size=50, total=1
        )

    async def get_run(self, organization_id: str, run_id: UUID) -> OrchestrationRunDTO:
        return _run_dto(run_id=str(run_id))

    async def sync_status(
        self, organization_id: str, *, cloud_account_id: UUID | None = None
    ) -> SyncStatusDTO:
        return SyncStatusDTO(
            organization_id=organization_id,
            accounts=[{"account_id": str(ACCOUNT), "sync_status": "SYNCED"}],
            last_orchestration=None,
            aggregated_status="SYNCED",
        )

    async def diagnostics(self, organization_id: str) -> PlatformDiagnosticsDTO:
        return PlatformDiagnosticsDTO(
            organization_id=organization_id,
            operation_id="op_d",
            health=await self.health(),
            last_run=_run_dto(),
            sync=await self.sync_status(organization_id),
            notes=["audit"],
        )


@pytest.fixture
def application() -> FastAPI:
    app = FastAPI()
    app.add_middleware(ErrorHandlerMiddleware)
    app.include_router(cloud_platform_router, prefix="/api/v1")

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

    from redforge.api.dependencies import get_organization_service

    app.dependency_overrides[get_tenant_context] = _tenant
    app.dependency_overrides[get_cloud_platform_service] = lambda: _FakePlatformService()
    app.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    return app


@pytest.fixture
async def client(application: FastAPI) -> Any:
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_health_forbidden_without_org_read() -> None:
    app = FastAPI()
    app.add_middleware(ErrorHandlerMiddleware)
    app.include_router(cloud_platform_router, prefix="/api/v1")

    async def _tenant() -> TenantContext:
        return TenantContext(
            user_id="01HXUSER000000000000000001",
            email="viewer@example.com",
            organization_id=ORG,
            role=MembershipRole.VIEWER,
            permissions=frozenset(),  # no ORG_READ
        )

    class _OrgStub:
        async def get_by_id(self, organization_id: str) -> object:
            class _Org:
                status = "active"

            return _Org()

    from redforge.api.dependencies import get_organization_service

    app.dependency_overrides[get_tenant_context] = _tenant
    app.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    app.dependency_overrides[get_cloud_platform_service] = lambda: _FakePlatformService()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/v1/cloud-foundation/platform/health")
    assert resp.status_code in {401, 403}


@pytest.mark.asyncio
async def test_health_shape(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/cloud-foundation/platform/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "healthy"
    assert isinstance(body["packages"], list)
    assert body["packages"][0]["package"]


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/cloud-foundation/platform/health",
        "/api/v1/cloud-foundation/platform/readiness",
        "/api/v1/cloud-foundation/platform/summary",
        "/api/v1/cloud-foundation/platform/runs",
        "/api/v1/cloud-foundation/platform/sync/status",
        "/api/v1/cloud-foundation/platform/diagnostics",
        "/api/v1/cloud-foundation/platform/validate/report",
    ],
)
@pytest.mark.asyncio
async def test_get_endpoints_ok(client: AsyncClient, path: str) -> None:
    resp = await client.get(path)
    assert resp.status_code == 200


@pytest.mark.parametrize(
    "package",
    [
        "foundation",
        "inventory",
        "identity",
        "cspm",
        "kubernetes",
        "runtime",
        "risk",
        "security_graph",
        "compliance",
    ],
)
@pytest.mark.asyncio
async def test_health_package(client: AsyncClient, package: str) -> None:
    resp = await client.get(f"/api/v1/cloud-foundation/platform/health/{package}")
    assert resp.status_code == 200
    assert resp.json()["package"] == package


@pytest.mark.asyncio
async def test_validate_post(client: AsyncClient) -> None:
    resp = await client.post("/api/v1/cloud-foundation/platform/validate")
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall_passed"] is True
    assert len(body["checks"]) >= 1


@pytest.mark.asyncio
async def test_orchestrate_with_fake(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/cloud-foundation/platform/orchestrate",
        json={
            "cloud_account_id": str(ACCOUNT),
            "fail_fast": False,
            "include_k8s": False,
            "include_runtime": False,
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "COMPLETED"
    assert body["operation_id"]
    assert body["steps"]


@pytest.mark.asyncio
async def test_get_run(client: AsyncClient) -> None:
    resp = await client.get(f"/api/v1/cloud-foundation/platform/runs/{RUN_ID}")
    assert resp.status_code == 200
    assert resp.json()["run_id"] == str(RUN_ID)


@pytest.mark.parametrize(
    "payload",
    [
        {"cloud_account_id": str(uuid4()), "include_k8s": True},
        {"cloud_account_id": str(uuid4()), "include_runtime": True, "runtime_events": []},
        {"organization_wide": True},
        {"cloud_account_id": str(uuid4()), "fail_fast": True},
    ],
)
@pytest.mark.asyncio
async def test_orchestrate_payload_matrix(
    client: AsyncClient, payload: dict[str, Any]
) -> None:
    resp = await client.post(
        "/api/v1/cloud-foundation/platform/orchestrate", json=payload
    )
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_invalid_run_uuid_rejected(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/cloud-foundation/platform/runs/not-a-uuid")
    assert resp.status_code == 422
