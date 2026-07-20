"""M26 Phase 8 Cloud Platform Integration Layer APIs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_cloud_platform_service
from redforge.api.security import TenantContext, require_permission
from redforge.application.cloud_security.platform.dtos import OrchestratePlatformCommand
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.cloud_security.platform.service import CloudPlatformService

router = APIRouter(prefix="/cloud-foundation", tags=["cloud-foundation"])


class OrchestrateRequest(BaseModel):
    cloud_account_id: UUID | None = None
    organization_wide: bool = False
    fail_fast: bool = False
    include_k8s: bool = False
    include_runtime: bool = False
    runtime_events: list[dict[str, Any]] = Field(default_factory=list)
    cloud_asset_id: UUID | None = None
    correlation_id: str = ""
    request_id: str = ""


class StepResultResponse(BaseModel):
    step_name: str
    status: str
    started_at: str | None = None
    completed_at: str | None = None
    duration_ms: float | None = None
    message: str = ""
    error: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class OrchestrationRunResponse(BaseModel):
    run_id: str
    organization_id: str
    scope: str
    target_id: str
    status: str
    steps: list[StepResultResponse]
    diagnostics: dict[str, Any] = Field(default_factory=dict)
    operation_id: str
    correlation_id: str = ""
    request_id: str = ""
    started_at: str
    completed_at: str | None = None
    row_version: int = 1


class OrchestrationRunPageResponse(BaseModel):
    items: list[OrchestrationRunResponse]
    page: int
    size: int
    total: int


class PackageHealthResponse(BaseModel):
    package: str
    status: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class PlatformHealthResponse(BaseModel):
    overall: str
    packages: list[PackageHealthResponse]
    checked_at: str
    operation_id: str = ""


class ValidationCheckResponse(BaseModel):
    name: str
    passed: bool
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ValidationReportResponse(BaseModel):
    organization_id: str
    overall_passed: bool
    checks: list[ValidationCheckResponse]
    created_at: str
    operation_id: str = ""


class PlatformSummaryResponse(BaseModel):
    organization_id: str
    account_count: int
    provider_count: int
    last_run_status: str | None = None
    last_run_id: str | None = None
    last_run_at: str | None = None
    health_overall: str
    validation_passed: bool | None = None


class SyncStatusResponse(BaseModel):
    organization_id: str
    accounts: list[dict[str, Any]]
    last_orchestration: dict[str, Any] | None = None
    aggregated_status: str


class PlatformDiagnosticsResponse(BaseModel):
    organization_id: str
    operation_id: str
    health: PlatformHealthResponse
    last_run: OrchestrationRunResponse | None = None
    sync: SyncStatusResponse
    notes: list[str] = Field(default_factory=list)


def _run_response(dto: Any) -> OrchestrationRunResponse:
    return OrchestrationRunResponse(
        run_id=dto.run_id,
        organization_id=dto.organization_id,
        scope=dto.scope,
        target_id=dto.target_id,
        status=dto.status,
        steps=[
            StepResultResponse(
                step_name=s.step_name,
                status=s.status,
                started_at=s.started_at.isoformat() if s.started_at else None,
                completed_at=s.completed_at.isoformat() if s.completed_at else None,
                duration_ms=s.duration_ms,
                message=s.message,
                error=s.error,
                details=dict(s.details),
            )
            for s in dto.steps
        ],
        diagnostics=dict(dto.diagnostics),
        operation_id=dto.operation_id,
        correlation_id=dto.correlation_id,
        request_id=dto.request_id,
        started_at=dto.started_at.isoformat(),
        completed_at=dto.completed_at.isoformat() if dto.completed_at else None,
        row_version=dto.row_version,
    )


def _health_response(dto: Any) -> PlatformHealthResponse:
    return PlatformHealthResponse(
        overall=dto.overall,
        packages=[
            PackageHealthResponse(
                package=p.package,
                status=p.status,
                message=p.message,
                details=dict(p.details),
            )
            for p in dto.packages
        ],
        checked_at=dto.checked_at.isoformat(),
        operation_id=dto.operation_id,
    )


def _validation_response(dto: Any) -> ValidationReportResponse:
    return ValidationReportResponse(
        organization_id=dto.organization_id,
        overall_passed=dto.overall_passed,
        checks=[
            ValidationCheckResponse(
                name=c.name,
                passed=c.passed,
                message=c.message,
                details=dict(c.details),
            )
            for c in dto.checks
        ],
        created_at=dto.created_at.isoformat(),
        operation_id=dto.operation_id,
    )


@router.get("/platform/health", response_model=PlatformHealthResponse)
async def platform_health(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CloudPlatformService = Depends(get_cloud_platform_service),
) -> PlatformHealthResponse:
    _ = tenant
    return _health_response(await service.health())


@router.get("/platform/health/{package}", response_model=PackageHealthResponse)
async def platform_health_package(
    package: str,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CloudPlatformService = Depends(get_cloud_platform_service),
) -> PackageHealthResponse:
    _ = tenant
    dto = await service.health_package(package)
    return PackageHealthResponse(
        package=dto.package,
        status=dto.status,
        message=dto.message,
        details=dict(dto.details),
    )


@router.get("/platform/readiness", response_model=PlatformHealthResponse)
async def platform_readiness(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CloudPlatformService = Depends(get_cloud_platform_service),
) -> PlatformHealthResponse:
    return _health_response(await service.readiness(tenant.organization_id))


@router.get("/platform/summary", response_model=PlatformSummaryResponse)
async def platform_summary(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CloudPlatformService = Depends(get_cloud_platform_service),
) -> PlatformSummaryResponse:
    dto = await service.summary(tenant.organization_id)
    return PlatformSummaryResponse(
        organization_id=dto.organization_id,
        account_count=dto.account_count,
        provider_count=dto.provider_count,
        last_run_status=dto.last_run_status,
        last_run_id=dto.last_run_id,
        last_run_at=dto.last_run_at.isoformat() if dto.last_run_at else None,
        health_overall=dto.health_overall,
        validation_passed=dto.validation_passed,
    )


@router.post(
    "/platform/validate",
    response_model=ValidationReportResponse,
    status_code=status.HTTP_200_OK,
)
async def platform_validate(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: CloudPlatformService = Depends(get_cloud_platform_service),
) -> ValidationReportResponse:
    return _validation_response(await service.validate(tenant.organization_id))


@router.get("/platform/validate/report", response_model=ValidationReportResponse | None)
async def platform_validate_report(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CloudPlatformService = Depends(get_cloud_platform_service),
) -> ValidationReportResponse | None:
    dto = await service.last_validation_report(tenant.organization_id)
    if dto is None:
        return None
    return _validation_response(dto)


@router.post(
    "/platform/orchestrate",
    response_model=OrchestrationRunResponse,
    status_code=status.HTTP_201_CREATED,
)
async def platform_orchestrate(
    body: OrchestrateRequest,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: CloudPlatformService = Depends(get_cloud_platform_service),
) -> OrchestrationRunResponse:
    result = await service.orchestrate(
        OrchestratePlatformCommand(
            organization_id=tenant.organization_id,
            cloud_account_id=body.cloud_account_id,
            organization_wide=body.organization_wide,
            fail_fast=body.fail_fast,
            include_k8s=body.include_k8s,
            include_runtime=body.include_runtime,
            runtime_events=list(body.runtime_events),
            cloud_asset_id=body.cloud_asset_id,
            correlation_id=body.correlation_id,
            request_id=body.request_id,
        )
    )
    return _run_response(result)


@router.get("/platform/runs", response_model=OrchestrationRunPageResponse)
async def platform_list_runs(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CloudPlatformService = Depends(get_cloud_platform_service),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    status_filter: str | None = Query(None, alias="status"),
) -> OrchestrationRunPageResponse:
    dto = await service.list_runs(
        tenant.organization_id, page=page, size=size, status=status_filter
    )
    return OrchestrationRunPageResponse(
        items=[_run_response(i) for i in dto.items],
        page=dto.page,
        size=dto.size,
        total=dto.total,
    )


@router.get("/platform/runs/{run_id}", response_model=OrchestrationRunResponse)
async def platform_get_run(
    run_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CloudPlatformService = Depends(get_cloud_platform_service),
) -> OrchestrationRunResponse:
    return _run_response(await service.get_run(tenant.organization_id, run_id))


@router.get("/platform/sync/status", response_model=SyncStatusResponse)
async def platform_sync_status(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CloudPlatformService = Depends(get_cloud_platform_service),
    cloud_account_id: UUID | None = None,
) -> SyncStatusResponse:
    dto = await service.sync_status(
        tenant.organization_id, cloud_account_id=cloud_account_id
    )
    return SyncStatusResponse(
        organization_id=dto.organization_id,
        accounts=list(dto.accounts),
        last_orchestration=dto.last_orchestration,
        aggregated_status=dto.aggregated_status,
    )


@router.get("/platform/diagnostics", response_model=PlatformDiagnosticsResponse)
async def platform_diagnostics(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CloudPlatformService = Depends(get_cloud_platform_service),
) -> PlatformDiagnosticsResponse:
    dto = await service.diagnostics(tenant.organization_id)
    return PlatformDiagnosticsResponse(
        organization_id=dto.organization_id,
        operation_id=dto.operation_id,
        health=_health_response(dto.health),
        last_run=_run_response(dto.last_run) if dto.last_run else None,
        sync=SyncStatusResponse(
            organization_id=dto.sync.organization_id,
            accounts=list(dto.sync.accounts),
            last_orchestration=dto.sync.last_orchestration,
            aggregated_status=dto.sync.aggregated_status,
        ),
        notes=list(dto.notes),
    )
