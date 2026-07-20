"""Engagement and target-authorization API routes."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from engagement.api.dependencies import EngagementServiceDep, PrincipalIdDep, TenantIdDep
from engagement.api.schemas.engagement_schemas import (
    AddParticipantRequest,
    CloseEngagementRequest,
    CreateEngagementRequest,
    DefineScopeRequest,
    EngagementResponse,
    GrantApprovalRequest,
    GrantTargetAuthorizationRequest,
    ListEngagementsResponse,
    ListTargetAuthorizationsResponse,
    RemoveParticipantRequest,
    ResumeEngagementRequest,
    RevokeTargetAuthorizationRequest,
    ScopeExpansionRequest,
    SetRoeRequest,
    SetWindowRequest,
    SignRoeRequest,
    SuspendEngagementRequest,
    SuspendTargetAuthorizationRequest,
    TargetAuthorizationResponse,
)
from engagement.application.commands.engagement_commands import (
    ActivateEngagementCommand,
    AddParticipantCommand,
    ApproveScopeExpansionCommand,
    ArchiveEngagementCommand,
    CloseEngagementCommand,
    CreateEngagementCommand,
    DefineTargetScopeCommand,
    GrantEngagementApprovalCommand,
    GrantTargetAuthorizationCommand,
    RemoveParticipantCommand,
    RequestScopeExpansionCommand,
    ResumeEngagementCommand,
    RevokeTargetAuthorizationCommand,
    SetEngagementWindowCommand,
    SetRulesOfEngagementCommand,
    SignRulesOfEngagementCommand,
    SubmitEngagementForApprovalCommand,
    SuspendEngagementCommand,
    SuspendTargetAuthorizationCommand,
)
from engagement.application.queries.engagement_queries import (
    GetEngagementQuery,
    GetTargetAuthorizationQuery,
    ListEngagementsQuery,
    ListTargetAuthorizationsQuery,
)
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

engagements_router = APIRouter()
target_authorizations_router = APIRouter()


@engagements_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=EngagementResponse,
)
async def create_engagement(
    body: CreateEngagementRequest,
    response: Response,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> EngagementResponse:
    dto = await svc.create_engagement(
        CreateEngagementCommand(
            tenant_id=tenant_id,
            name=body.name,
            classification=body.classification,
            owner_id=body.owner_id,
            required_approver_count=body.required_approver_count,
            actor=str(principal_id),
        )
    )
    response.headers["Location"] = f"/api/v1/engagements/{dto.engagement_id}"
    return EngagementResponse.from_dto(dto)


@engagements_router.get("", response_model=ListEngagementsResponse)
async def list_engagements(
    tenant_id: TenantIdDep,
    svc: EngagementServiceDep,
    state: str | None = Query(default=None),
    active_only: bool = Query(default=False),
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> ListEngagementsResponse:
    items = await svc.list_engagements(
        ListEngagementsQuery(
            tenant_id=tenant_id, state=state, active_only=active_only
        )
    )
    return ListEngagementsResponse(
        items=[EngagementResponse.from_dto(i) for i in items]
    )


@engagements_router.get("/{engagement_id}", response_model=EngagementResponse)
async def get_engagement(
    engagement_id: UUID,
    tenant_id: TenantIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> EngagementResponse:
    dto = await svc.get_engagement(
        GetEngagementQuery(tenant_id=tenant_id, engagement_id=engagement_id)
    )
    return EngagementResponse.from_dto(dto)


@engagements_router.post(
    "/{engagement_id}/scope",
    response_model=EngagementResponse,
)
async def define_scope(
    engagement_id: UUID,
    body: DefineScopeRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_PLANNER)),
) -> EngagementResponse:
    dto = await svc.define_target_scope(
        DefineTargetScopeCommand(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            asset_ids=body.asset_ids,
            actor=str(principal_id),
        )
    )
    return EngagementResponse.from_dto(dto)


@engagements_router.post(
    "/{engagement_id}/roe",
    response_model=EngagementResponse,
)
async def set_roe(
    engagement_id: UUID,
    body: SetRoeRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_PLANNER)),
) -> EngagementResponse:
    dto = await svc.set_rules_of_engagement(
        SetRulesOfEngagementCommand(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            allowed_techniques=body.allowed_techniques,
            forbidden_targets=body.forbidden_targets,
            rate_limits=body.rate_limits,
            escalation_contacts=body.escalation_contacts,
            actor=str(principal_id),
        )
    )
    return EngagementResponse.from_dto(dto)


@engagements_router.post(
    "/{engagement_id}/roe/sign",
    response_model=EngagementResponse,
)
async def sign_roe(
    engagement_id: UUID,
    body: SignRoeRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> EngagementResponse:
    dto = await svc.sign_rules_of_engagement(
        SignRulesOfEngagementCommand(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            owner_id=body.owner_id,
            signature=body.signature,
            actor=str(principal_id),
        )
    )
    return EngagementResponse.from_dto(dto)


@engagements_router.post(
    "/{engagement_id}/window",
    response_model=EngagementResponse,
)
async def set_window(
    engagement_id: UUID,
    body: SetWindowRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_PLANNER)),
) -> EngagementResponse:
    dto = await svc.set_window(
        SetEngagementWindowCommand(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            authorized_start=body.authorized_start,
            authorized_end=body.authorized_end,
            operational_hours=body.operational_hours,
            actor=str(principal_id),
        )
    )
    return EngagementResponse.from_dto(dto)


@engagements_router.post(
    "/{engagement_id}/participants",
    response_model=EngagementResponse,
)
async def add_participant(
    engagement_id: UUID,
    body: AddParticipantRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> EngagementResponse:
    dto = await svc.add_participant(
        AddParticipantCommand(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            operator_id=body.operator_id,
            role=body.role,
            actor=str(principal_id),
        )
    )
    return EngagementResponse.from_dto(dto)


@engagements_router.delete(
    "/{engagement_id}/participants",
    response_model=EngagementResponse,
)
async def remove_participant(
    engagement_id: UUID,
    body: RemoveParticipantRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> EngagementResponse:
    dto = await svc.remove_participant(
        RemoveParticipantCommand(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            operator_id=body.operator_id,
            actor=str(principal_id),
        )
    )
    return EngagementResponse.from_dto(dto)


@engagements_router.post(
    "/{engagement_id}/submit",
    response_model=EngagementResponse,
)
async def submit_for_approval(
    engagement_id: UUID,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_PLANNER)),
) -> EngagementResponse:
    dto = await svc.submit_for_approval(
        SubmitEngagementForApprovalCommand(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            actor=str(principal_id),
        )
    )
    return EngagementResponse.from_dto(dto)


@engagements_router.post(
    "/{engagement_id}/approvals",
    response_model=EngagementResponse,
)
async def grant_approval(
    engagement_id: UUID,
    body: GrantApprovalRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_APPROVER)),
) -> EngagementResponse:
    dto = await svc.grant_approval(
        GrantEngagementApprovalCommand(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            approver_id=body.approver_id,
            signature=body.signature,
            actor=str(principal_id),
        )
    )
    return EngagementResponse.from_dto(dto)


@engagements_router.post(
    "/{engagement_id}/activate",
    response_model=EngagementResponse,
)
async def activate_engagement(
    engagement_id: UUID,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> EngagementResponse:
    dto = await svc.activate(
        ActivateEngagementCommand(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            actor=str(principal_id),
        )
    )
    return EngagementResponse.from_dto(dto)


@engagements_router.post(
    "/{engagement_id}/suspend",
    response_model=EngagementResponse,
)
async def suspend_engagement(
    engagement_id: UUID,
    body: SuspendEngagementRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> EngagementResponse:
    dto = await svc.suspend(
        SuspendEngagementCommand(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            reason=body.reason,
            authority=body.authority,
            actor=str(principal_id),
        )
    )
    return EngagementResponse.from_dto(dto)


@engagements_router.post(
    "/{engagement_id}/resume",
    response_model=EngagementResponse,
)
async def resume_engagement(
    engagement_id: UUID,
    body: ResumeEngagementRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> EngagementResponse:
    dto = await svc.resume(
        ResumeEngagementCommand(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            authority=body.authority,
            actor=str(principal_id),
        )
    )
    return EngagementResponse.from_dto(dto)


@engagements_router.post(
    "/{engagement_id}/close",
    response_model=EngagementResponse,
)
async def close_engagement(
    engagement_id: UUID,
    body: CloseEngagementRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> EngagementResponse:
    dto = await svc.close(
        CloseEngagementCommand(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            reason=body.reason,
            actor=str(principal_id),
        )
    )
    return EngagementResponse.from_dto(dto)


@engagements_router.post(
    "/{engagement_id}/archive",
    response_model=EngagementResponse,
)
async def archive_engagement(
    engagement_id: UUID,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> EngagementResponse:
    dto = await svc.archive(
        ArchiveEngagementCommand(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            actor=str(principal_id),
        )
    )
    return EngagementResponse.from_dto(dto)


@engagements_router.post(
    "/{engagement_id}/scope-expansion",
    response_model=EngagementResponse,
)
async def request_scope_expansion(
    engagement_id: UUID,
    body: ScopeExpansionRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> EngagementResponse:
    dto = await svc.request_scope_expansion(
        RequestScopeExpansionCommand(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            asset_ids=body.asset_ids,
            actor=str(principal_id),
        )
    )
    return EngagementResponse.from_dto(dto)


@engagements_router.post(
    "/{engagement_id}/scope-expansion/approve",
    response_model=EngagementResponse,
)
async def approve_scope_expansion(
    engagement_id: UUID,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_APPROVER)),
) -> EngagementResponse:
    dto = await svc.approve_scope_expansion(
        ApproveScopeExpansionCommand(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            actor=str(principal_id),
        )
    )
    return EngagementResponse.from_dto(dto)


@target_authorizations_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=TargetAuthorizationResponse,
)
async def grant_target_authorization(
    body: GrantTargetAuthorizationRequest,
    response: Response,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_OPERATOR)),
) -> TargetAuthorizationResponse:
    dto = await svc.grant_target_authorization(
        GrantTargetAuthorizationCommand(
            tenant_id=tenant_id,
            engagement_id=body.engagement_id,
            asset_id=body.asset_id,
            technique_ids=body.technique_ids,
            impact_ceiling=body.impact_ceiling,
            max_execution_count=body.max_execution_count,
            valid_until=body.valid_until,
            granted_by=body.granted_by,
            destruct_approval_granted=body.destruct_approval_granted,
            phase_id=body.phase_id,
            actor=str(principal_id),
        )
    )
    response.headers["Location"] = (
        f"/api/v1/target-authorizations/{dto.authorization_id}"
    )
    return TargetAuthorizationResponse.from_dto(dto)


@target_authorizations_router.get(
    "/{authorization_id}",
    response_model=TargetAuthorizationResponse,
)
async def get_target_authorization(
    authorization_id: UUID,
    tenant_id: TenantIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> TargetAuthorizationResponse:
    dto = await svc.get_target_authorization(
        GetTargetAuthorizationQuery(
            tenant_id=tenant_id, authorization_id=authorization_id
        )
    )
    return TargetAuthorizationResponse.from_dto(dto)


@target_authorizations_router.get(
    "",
    response_model=ListTargetAuthorizationsResponse,
)
async def list_target_authorizations(
    tenant_id: TenantIdDep,
    svc: EngagementServiceDep,
    engagement_id: UUID = Query(...),
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> ListTargetAuthorizationsResponse:
    items = await svc.list_target_authorizations(
        ListTargetAuthorizationsQuery(
            tenant_id=tenant_id, engagement_id=engagement_id
        )
    )
    return ListTargetAuthorizationsResponse(
        items=[TargetAuthorizationResponse.from_dto(i) for i in items]
    )


@target_authorizations_router.post(
    "/{authorization_id}/revoke",
    response_model=TargetAuthorizationResponse,
)
async def revoke_target_authorization(
    authorization_id: UUID,
    body: RevokeTargetAuthorizationRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> TargetAuthorizationResponse:
    dto = await svc.revoke_target_authorization(
        RevokeTargetAuthorizationCommand(
            tenant_id=tenant_id,
            authorization_id=authorization_id,
            reason=body.reason,
            revoked_by=body.revoked_by,
            actor=str(principal_id),
        )
    )
    return TargetAuthorizationResponse.from_dto(dto)


@target_authorizations_router.post(
    "/{authorization_id}/suspend",
    response_model=TargetAuthorizationResponse,
)
async def suspend_target_authorization(
    authorization_id: UUID,
    body: SuspendTargetAuthorizationRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EngagementServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> TargetAuthorizationResponse:
    dto = await svc.suspend_target_authorization(
        SuspendTargetAuthorizationCommand(
            tenant_id=tenant_id,
            authorization_id=authorization_id,
            reason=body.reason,
            actor=str(principal_id),
        )
    )
    return TargetAuthorizationResponse.from_dto(dto)
