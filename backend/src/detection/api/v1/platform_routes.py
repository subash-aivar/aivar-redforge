"""Phase 5 internal APIs — projection health/replay, coverage refresh, platform."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from detection.api.dependencies import (
    PlatformOrchestrationDep,
    ProjectionServiceDep,
    TenantIdDep,
)
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

platform_router = APIRouter()


@platform_router.get("/projections/health")
async def projection_health(
    svc: ProjectionServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> dict[str, Any]:
    return svc.projection_health()


@platform_router.get("/projections/status")
async def projection_status(
    svc: ProjectionServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> dict[str, Any]:
    return svc.projection_status()


@platform_router.post("/projections/replay")
async def projection_replay(
    tenant_id: TenantIdDep,
    svc: ProjectionServiceDep,
    from_position: int = Query(0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> dict[str, Any]:
    return await svc.replay(tenant_id=tenant_id, from_position=from_position)


@platform_router.post("/projections/reconcile")
async def projection_reconcile(
    tenant_id: TenantIdDep,
    svc: ProjectionServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> dict[str, Any]:
    return await svc.reconcile(tenant_id)


@platform_router.post("/read-models/refresh")
async def read_model_refresh(
    tenant_id: TenantIdDep,
    svc: ProjectionServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> dict[str, Any]:
    return await svc.read_model_refresh(tenant_id)


@platform_router.post("/coverage/refresh")
async def coverage_refresh(
    tenant_id: TenantIdDep,
    svc: ProjectionServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> dict[str, Any]:
    return await svc.coverage_refresh(tenant_id)


@platform_router.get("/read-models/finding-summary")
async def get_finding_summary(
    tenant_id: TenantIdDep,
    svc: ProjectionServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> dict[str, Any] | None:
    return await svc.get_finding_summary(tenant_id)


@platform_router.get("/read-models/coverage-matrix")
async def get_coverage_matrix(
    tenant_id: TenantIdDep,
    svc: ProjectionServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> dict[str, Any] | None:
    return await svc.get_coverage_matrix(tenant_id)


@platform_router.get("/platform/readiness")
async def platform_readiness(
    tenant_id: TenantIdDep,
    svc: ProjectionServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> dict[str, Any]:
    return await svc.platform_readiness(tenant_id)


@platform_router.get("/platform/validation")
async def platform_validation(
    tenant_id: TenantIdDep,
    svc: ProjectionServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> dict[str, Any]:
    return await svc.platform_validation(tenant_id)


@platform_router.get("/platform/status")
async def platform_status(
    tenant_id: TenantIdDep,
    orch: PlatformOrchestrationDep,
    _tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> dict[str, Any]:
    return await orch.platform_status(tenant_id)


@platform_router.get("/platform/lifecycle")
async def platform_lifecycle(
    orch: PlatformOrchestrationDep,
    _tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> dict[str, Any]:
    return orch.lifecycle_map()
