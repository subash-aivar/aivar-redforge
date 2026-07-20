"""Operation API routers."""

from __future__ import annotations

from dataclasses import asdict
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from operation.api.dependencies import OperationServiceDep, PrincipalIdDep, TenantIdDep
from operation.api.schemas.operation_schemas import (
    AddExecutionStepRequest,
    AddStepDependencyRequest,
    ApproveOperationRequest,
    CreateOperationRequest,
    ExecutionPlanVersionResponse,
    ListOperationsResponse,
    OperationResponse,
    PlanValidationResponse,
    SetObjectivesRequest,
    SignExecutionPlanRequest,
)
from operation.application.commands.operation_commands import (
    AddExecutionStep,
    AddStepDependency,
    ApproveOperation,
    CreateOperation,
    QueueOperation,
    RemoveExecutionStep,
    SetOperationObjectives,
    SignExecutionPlan,
    SubmitOperationForApproval,
    ValidateExecutionPlan,
)
from operation.application.dtos.operation_dtos import OperationDTO
from operation.application.queries.operation_queries import (
    GetOperation,
    ListOperationsByEngagement,
)
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

operations_router = APIRouter()


def _operation_response(dto: OperationDTO) -> OperationResponse:
    return OperationResponse.model_validate(asdict(dto))


@operations_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=OperationResponse,
)
async def create_operation(
    body: CreateOperationRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: OperationServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_PLANNER)),
) -> OperationResponse:
    dto = await svc.create_operation(
        CreateOperation(
            tenant_id=tenant_id,
            engagement_id=UUID(body.engagement_id),
            name=body.name,
            classification=body.classification,
        )
    )
    response.headers["Location"] = f"/api/v1/operations/{dto.id}"
    return _operation_response(dto)


@operations_router.get("/{operation_id}", response_model=OperationResponse)
async def get_operation(
    operation_id: UUID,
    tenant_id: TenantIdDep,
    svc: OperationServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> OperationResponse:
    dto = await svc.get_operation(
        GetOperation(tenant_id=tenant_id, operation_id=operation_id)
    )
    return _operation_response(dto)


@operations_router.get("", response_model=ListOperationsResponse)
async def list_operations(
    tenant_id: TenantIdDep,
    svc: OperationServiceDep,
    engagement_id: UUID = Query(...),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> ListOperationsResponse:
    items = await svc.list_by_engagement(
        ListOperationsByEngagement(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            limit=limit,
            offset=offset,
        )
    )
    return ListOperationsResponse(
        items=[_operation_response(i) for i in items],
        count=len(items),
    )


@operations_router.post(
    "/{operation_id}/steps",
    response_model=OperationResponse,
)
async def add_execution_step(
    operation_id: UUID,
    body: AddExecutionStepRequest,
    tenant_id: TenantIdDep,
    svc: OperationServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_PLANNER)),
) -> OperationResponse:
    dto = await svc.add_execution_step(
        AddExecutionStep(
            tenant_id=tenant_id,
            operation_id=operation_id,
            name=body.name,
            step_type=body.step_type,
            max_duration_seconds=body.max_duration_seconds,
            rollback_on_failure=body.rollback_on_failure,
            continue_on_failure=body.continue_on_failure,
            technique_payload_id=body.technique_payload_id,
            technique_id=body.technique_id,
            target_asset_id=UUID(body.target_asset_id) if body.target_asset_id else None,
            impact_ceiling=body.impact_ceiling,
            modifies_persistent_state=body.modifies_persistent_state,
            mitre_technique_id=body.mitre_technique_id,
            mitre_tactic=body.mitre_tactic,
            rate_limit_max=body.rate_limit_max,
            rate_limit_window_seconds=body.rate_limit_window_seconds,
            window_allowed_days=(
                tuple(body.window_allowed_days) if body.window_allowed_days else None
            ),
            window_start_hour=body.window_start_hour,
            window_end_hour=body.window_end_hour,
            description=body.description,
        )
    )
    return _operation_response(dto)


@operations_router.delete(
    "/{operation_id}/steps/{step_id}",
    response_model=OperationResponse,
)
async def remove_execution_step(
    operation_id: UUID,
    step_id: UUID,
    tenant_id: TenantIdDep,
    svc: OperationServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_PLANNER)),
) -> OperationResponse:
    dto = await svc.remove_execution_step(
        RemoveExecutionStep(
            tenant_id=tenant_id,
            operation_id=operation_id,
            step_id=step_id,
        )
    )
    return _operation_response(dto)


@operations_router.post(
    "/{operation_id}/dependencies",
    response_model=OperationResponse,
)
async def add_step_dependency(
    operation_id: UUID,
    body: AddStepDependencyRequest,
    tenant_id: TenantIdDep,
    svc: OperationServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_PLANNER)),
) -> OperationResponse:
    dto = await svc.add_step_dependency(
        AddStepDependency(
            tenant_id=tenant_id,
            operation_id=operation_id,
            from_step_id=UUID(body.from_step_id),
            to_step_id=UUID(body.to_step_id),
        )
    )
    return _operation_response(dto)


@operations_router.put(
    "/{operation_id}/objectives",
    response_model=OperationResponse,
)
async def set_objectives(
    operation_id: UUID,
    body: SetObjectivesRequest,
    tenant_id: TenantIdDep,
    svc: OperationServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_PLANNER)),
) -> OperationResponse:
    dto = await svc.set_objectives(
        SetOperationObjectives(
            tenant_id=tenant_id,
            operation_id=operation_id,
            objectives=tuple(
                (o.description, o.success_criteria, o.is_primary) for o in body.objectives
            ),
        )
    )
    return _operation_response(dto)


@operations_router.post(
    "/{operation_id}/validate-plan",
    response_model=PlanValidationResponse,
)
async def validate_execution_plan(
    operation_id: UUID,
    tenant_id: TenantIdDep,
    svc: OperationServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_PLANNER)),
) -> PlanValidationResponse:
    result = await svc.validate_execution_plan(
        ValidateExecutionPlan(tenant_id=tenant_id, operation_id=operation_id)
    )
    return PlanValidationResponse(
        operation_id=result.operation_id,
        valid=result.valid,
        message=result.message,
    )


@operations_router.post(
    "/{operation_id}/sign-plan",
    status_code=status.HTTP_201_CREATED,
)
async def sign_execution_plan(
    operation_id: UUID,
    body: SignExecutionPlanRequest,
    response: Response,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: OperationServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_PLANNER)),
) -> ExecutionPlanVersionResponse:
    dto = await svc.sign_execution_plan(
        SignExecutionPlan(
            tenant_id=tenant_id,
            operation_id=operation_id,
            operator_id=principal_id,
            signature=body.signature,
        )
    )
    response.headers["Location"] = f"/api/v1/execution-plan-versions/{dto.id}"
    return ExecutionPlanVersionResponse.model_validate(asdict(dto))


@operations_router.post(
    "/{operation_id}/submit-for-approval",
    response_model=OperationResponse,
)
async def submit_for_approval(
    operation_id: UUID,
    tenant_id: TenantIdDep,
    svc: OperationServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_PLANNER)),
) -> OperationResponse:
    dto = await svc.submit_for_approval(
        SubmitOperationForApproval(tenant_id=tenant_id, operation_id=operation_id)
    )
    return _operation_response(dto)


@operations_router.post(
    "/{operation_id}/approve",
    response_model=OperationResponse,
)
async def approve_operation(
    operation_id: UUID,
    body: ApproveOperationRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: OperationServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_APPROVER)),
) -> OperationResponse:
    dto = await svc.approve_operation(
        ApproveOperation(
            tenant_id=tenant_id,
            operation_id=operation_id,
            operator_id=principal_id,
            authority=body.authority,
            signature=body.signature,
        )
    )
    return _operation_response(dto)


@operations_router.post(
    "/{operation_id}/queue",
    response_model=OperationResponse,
)
async def queue_operation(
    operation_id: UUID,
    tenant_id: TenantIdDep,
    svc: OperationServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_OPERATOR)),
) -> OperationResponse:
    dto = await svc.queue_operation(
        QueueOperation(tenant_id=tenant_id, operation_id=operation_id)
    )
    return _operation_response(dto)
