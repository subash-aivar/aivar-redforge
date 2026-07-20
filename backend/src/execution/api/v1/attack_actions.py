"""Attack action API routes."""

from __future__ import annotations

from dataclasses import asdict
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from execution.api.dependencies import (
    ExecutionServiceDep,
    PrincipalIdDep,
    TenantIdDep,
)
from execution.api.schemas.execution_schemas import (
    AbortAttackActionRequest,
    AttackActionResponse,
    AuthorizeAndStartRequest,
    CompleteAttackActionRequest,
    FailAttackActionRequest,
)
from execution.application.commands.execution_commands import (
    AbortAttackAction,
    AuthorizeAndStartAttackAction,
    CompleteAttackAction,
    FailAttackAction,
)
from execution.application.queries.execution_queries import (
    GetAttackAction,
    ListAttackActionsByOperation,
)
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

attack_actions_router = APIRouter()


@attack_actions_router.post(
    "/authorize-and-start", response_model=AttackActionResponse, status_code=201
)
async def authorize_and_start(
    body: AuthorizeAndStartRequest,
    service: ExecutionServiceDep,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_OPERATOR)),
) -> AttackActionResponse:
    dto = await service.authorize_and_start_attack_action(
        AuthorizeAndStartAttackAction(
            tenant_id=tenant_id,
            engagement_id=body.engagement_id,
            operation_id=body.operation_id,
            step_id=body.step_id,
            target_id=body.target_id,
            technique_id=body.technique_id,
            technique_category=body.technique_category,
            impact_ceiling=body.impact_ceiling,
            operator_id=principal_id,
            worker_id=body.worker_id,
            action_parameters=body.action_parameters,
            rate_limit_max=body.rate_limit_max,
            rate_limit_window_seconds=body.rate_limit_window_seconds,
            presented_scope_hash=body.presented_scope_hash,
            presented_engagement_version=body.presented_engagement_version,
            network_zone=body.network_zone,
        )
    )
    return AttackActionResponse.model_validate(asdict(dto))


@attack_actions_router.post("/{action_id}/abort", response_model=AttackActionResponse)
async def abort_action(
    action_id: UUID,
    body: AbortAttackActionRequest,
    service: ExecutionServiceDep,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_OPERATOR)),
) -> AttackActionResponse:
    dto = await service.abort_attack_action(
        AbortAttackAction(
            tenant_id=tenant_id,
            action_id=action_id,
            abort_reason=body.abort_reason,
            authority_operator_id=principal_id,
        )
    )
    return AttackActionResponse.model_validate(asdict(dto))


@attack_actions_router.post("/{action_id}/complete", response_model=AttackActionResponse)
async def complete_action(
    action_id: UUID,
    body: CompleteAttackActionRequest,
    service: ExecutionServiceDep,
    tenant_id: TenantIdDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_OPERATOR)),
) -> AttackActionResponse:
    dto = await service.complete_attack_action(
        CompleteAttackAction(
            tenant_id=tenant_id,
            action_id=action_id,
            output_hash=body.output_hash,
            output_storage_ref=body.output_storage_ref,
        )
    )
    return AttackActionResponse.model_validate(asdict(dto))


@attack_actions_router.post("/{action_id}/fail", response_model=AttackActionResponse)
async def fail_action(
    action_id: UUID,
    body: FailAttackActionRequest,
    service: ExecutionServiceDep,
    tenant_id: TenantIdDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_OPERATOR)),
) -> AttackActionResponse:
    dto = await service.fail_attack_action(
        FailAttackAction(
            tenant_id=tenant_id,
            action_id=action_id,
            failure_reason=body.failure_reason,
        )
    )
    return AttackActionResponse.model_validate(asdict(dto))


@attack_actions_router.get("/{action_id}", response_model=AttackActionResponse)
async def get_action(
    action_id: UUID,
    service: ExecutionServiceDep,
    tenant_id: TenantIdDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> AttackActionResponse:
    dto = await service.get_attack_action(
        GetAttackAction(tenant_id=tenant_id, action_id=action_id)
    )
    return AttackActionResponse.model_validate(asdict(dto))


@attack_actions_router.get("", response_model=list[AttackActionResponse])
async def list_by_operation(
    service: ExecutionServiceDep,
    tenant_id: TenantIdDep,
    operation_id: UUID = Query(...),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> list[AttackActionResponse]:
    dtos = await service.list_attack_actions_by_operation(
        ListAttackActionsByOperation(
            tenant_id=tenant_id,
            operation_id=operation_id,
            limit=limit,
            offset=offset,
        )
    )
    return [AttackActionResponse.model_validate(asdict(d)) for d in dtos]
