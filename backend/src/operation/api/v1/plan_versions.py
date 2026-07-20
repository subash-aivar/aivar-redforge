"""Execution plan version API routers."""

from __future__ import annotations

from dataclasses import asdict
from uuid import UUID

from fastapi import APIRouter, Depends

from operation.api.dependencies import OperationServiceDep, TenantIdDep
from operation.api.schemas.operation_schemas import (
    ExecutionPlanVersionResponse,
    ListPlanVersionsResponse,
)
from operation.application.queries.operation_queries import (
    GetExecutionPlanVersion,
    ListPlanVersionsByOperation,
)
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

plan_versions_router = APIRouter()


@plan_versions_router.get(
    "/{plan_version_id}",
    response_model=ExecutionPlanVersionResponse,
)
async def get_plan_version(
    plan_version_id: UUID,
    tenant_id: TenantIdDep,
    svc: OperationServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> ExecutionPlanVersionResponse:
    dto = await svc.get_plan_version(
        GetExecutionPlanVersion(tenant_id=tenant_id, plan_version_id=plan_version_id)
    )
    return ExecutionPlanVersionResponse.model_validate(asdict(dto))


@plan_versions_router.get(
    "",
    response_model=ListPlanVersionsResponse,
)
async def list_plan_versions(
    tenant_id: TenantIdDep,
    svc: OperationServiceDep,
    operation_id: UUID,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> ListPlanVersionsResponse:
    items = await svc.list_plan_versions(
        ListPlanVersionsByOperation(tenant_id=tenant_id, operation_id=operation_id)
    )
    return ListPlanVersionsResponse(
        items=[ExecutionPlanVersionResponse.model_validate(asdict(i)) for i in items],
        count=len(items),
    )
