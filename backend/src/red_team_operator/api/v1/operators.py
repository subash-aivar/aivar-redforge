"""RedTeamOperator API router."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from red_team_operator.api.dependencies import (
    OperatorQueryServiceDep,
    OperatorServiceDep,
    TenantIdDep,
)
from red_team_operator.api.schemas.operator_schemas import (
    ActivateOperatorRequest,
    AddToEngagementRequest,
    ChangeClearanceRequest,
    GrantApprovalAuthorityRequest,
    ListOperatorsResponse,
    OperatorResponse,
    RevokeOperatorRequest,
    SuspendOperatorRequest,
)
from red_team_operator.application.commands.operator_commands import (
    ActivateOperatorCommand,
    AddOperatorToEngagementCommand,
    ChangeOperatorClearanceCommand,
    GrantApprovalAuthorityCommand,
    RemoveOperatorFromEngagementCommand,
    RevokeApprovalAuthorityCommand,
    RevokeOperatorCommand,
    SuspendOperatorCommand,
)
from red_team_operator.application.queries.operator_queries import (
    FindAuthorizedApproversQuery,
    GetOperatorQuery,
    ListOperatorsQuery,
)
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

operators_router = APIRouter()


@operators_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=OperatorResponse,
)
async def activate_operator(
    body: ActivateOperatorRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: OperatorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> OperatorResponse:
    dto = await svc.activate_operator(
        ActivateOperatorCommand(
            tenant_id=tenant_id,
            identity_ref=body.identity_ref,
            clearance_level=body.clearance_level,
            display_name=body.display_name,
            certifications=list(body.certifications),
            approval_scopes=list(body.approval_scopes),
            operator_id=body.operator_id,
        )
    )
    response.headers["Location"] = f"/api/v1/red-team-operators/{dto.operator_id}"
    return OperatorResponse.from_dto(dto)


@operators_router.get("", response_model=ListOperatorsResponse)
async def list_operators(
    tenant_id: TenantIdDep,
    query_svc: OperatorQueryServiceDep,
    include_inactive: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> ListOperatorsResponse:
    items = await query_svc.list_operators(
        ListOperatorsQuery(
            tenant_id=tenant_id,
            include_inactive=include_inactive,
            limit=limit,
            offset=offset,
        )
    )
    return ListOperatorsResponse(
        items=[OperatorResponse.from_dto(item) for item in items],
        total=len(items),
        limit=limit,
        offset=offset,
    )


@operators_router.get("/approvers", response_model=ListOperatorsResponse)
async def find_authorized_approvers(
    tenant_id: TenantIdDep,
    query_svc: OperatorQueryServiceDep,
    scope: str = Query(...),
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> ListOperatorsResponse:
    items = await query_svc.find_authorized_approvers(
        FindAuthorizedApproversQuery(tenant_id=tenant_id, scope=scope)
    )
    return ListOperatorsResponse(
        items=[OperatorResponse.from_dto(item) for item in items],
        total=len(items),
        limit=len(items),
        offset=0,
    )


@operators_router.get("/{operator_id}", response_model=OperatorResponse)
async def get_operator(
    operator_id: UUID,
    tenant_id: TenantIdDep,
    query_svc: OperatorQueryServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> OperatorResponse:
    dto = await query_svc.get_operator(
        GetOperatorQuery(tenant_id=tenant_id, operator_id=operator_id)
    )
    return OperatorResponse.from_dto(dto)


@operators_router.post("/{operator_id}/suspend", response_model=OperatorResponse)
async def suspend_operator(
    operator_id: UUID,
    body: SuspendOperatorRequest,
    tenant_id: TenantIdDep,
    svc: OperatorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> OperatorResponse:
    dto = await svc.suspend_operator(
        SuspendOperatorCommand(
            tenant_id=tenant_id,
            operator_id=operator_id,
            reason=body.reason,
            authority=body.authority,
        )
    )
    return OperatorResponse.from_dto(dto)


@operators_router.post("/{operator_id}/revoke", response_model=OperatorResponse)
async def revoke_operator(
    operator_id: UUID,
    body: RevokeOperatorRequest,
    tenant_id: TenantIdDep,
    svc: OperatorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> OperatorResponse:
    dto = await svc.revoke_operator(
        RevokeOperatorCommand(
            tenant_id=tenant_id,
            operator_id=operator_id,
            reason=body.reason,
            authority=body.authority,
        )
    )
    return OperatorResponse.from_dto(dto)


@operators_router.post("/{operator_id}/clearance", response_model=OperatorResponse)
async def change_clearance(
    operator_id: UUID,
    body: ChangeClearanceRequest,
    tenant_id: TenantIdDep,
    svc: OperatorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> OperatorResponse:
    dto = await svc.change_clearance(
        ChangeOperatorClearanceCommand(
            tenant_id=tenant_id,
            operator_id=operator_id,
            new_level=body.new_level,
            authority=body.authority,
        )
    )
    return OperatorResponse.from_dto(dto)


@operators_router.post("/{operator_id}/engagements", response_model=OperatorResponse)
async def add_to_engagement(
    operator_id: UUID,
    body: AddToEngagementRequest,
    tenant_id: TenantIdDep,
    svc: OperatorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> OperatorResponse:
    dto = await svc.add_to_engagement(
        AddOperatorToEngagementCommand(
            tenant_id=tenant_id,
            operator_id=operator_id,
            engagement_id=body.engagement_id,
        )
    )
    return OperatorResponse.from_dto(dto)


@operators_router.delete(
    "/{operator_id}/engagements/{engagement_id}",
    response_model=OperatorResponse,
)
async def remove_from_engagement(
    operator_id: UUID,
    engagement_id: UUID,
    tenant_id: TenantIdDep,
    svc: OperatorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> OperatorResponse:
    dto = await svc.remove_from_engagement(
        RemoveOperatorFromEngagementCommand(
            tenant_id=tenant_id,
            operator_id=operator_id,
            engagement_id=engagement_id,
        )
    )
    return OperatorResponse.from_dto(dto)


@operators_router.post(
    "/{operator_id}/approval-authority",
    response_model=OperatorResponse,
)
async def grant_approval_authority(
    operator_id: UUID,
    body: GrantApprovalAuthorityRequest,
    tenant_id: TenantIdDep,
    svc: OperatorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> OperatorResponse:
    dto = await svc.grant_approval_authority(
        GrantApprovalAuthorityCommand(
            tenant_id=tenant_id,
            operator_id=operator_id,
            scope=body.scope,
        )
    )
    return OperatorResponse.from_dto(dto)


@operators_router.delete(
    "/{operator_id}/approval-authority/{scope}",
    response_model=OperatorResponse,
)
async def revoke_approval_authority(
    operator_id: UUID,
    scope: str,
    tenant_id: TenantIdDep,
    svc: OperatorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> OperatorResponse:
    dto = await svc.revoke_approval_authority(
        RevokeApprovalAuthorityCommand(
            tenant_id=tenant_id,
            operator_id=operator_id,
            scope=scope,
        )
    )
    return OperatorResponse.from_dto(dto)
