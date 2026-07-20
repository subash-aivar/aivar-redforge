"""Kill switch API routes."""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends

from execution.api.dependencies import (
    ExecutionServiceDep,
    PrincipalIdDep,
    TenantIdDep,
)
from execution.api.schemas.execution_schemas import (
    KillSwitchResponse,
    ReArmKillSwitchRequest,
    ReleaseKillSwitchRequest,
    TriggerKillSwitchRequest,
)
from execution.application.commands.execution_commands import (
    ReArmKillSwitch,
    ReleaseKillSwitch,
    TriggerKillSwitch,
)
from execution.application.queries.execution_queries import GetKillSwitch
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

kill_switches_router = APIRouter()


@kill_switches_router.post("", response_model=KillSwitchResponse, status_code=201)
async def trigger_kill_switch(
    body: TriggerKillSwitchRequest,
    service: ExecutionServiceDep,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> KillSwitchResponse:
    dto = await service.trigger_kill_switch(
        TriggerKillSwitch(
            tenant_id=tenant_id,
            scope=body.scope,
            scope_ref=body.scope_ref,
            authority_operator_id=principal_id,
            authority_role=body.authority_role,
            reason=body.reason,
        )
    )
    return KillSwitchResponse.model_validate(asdict(dto))


@kill_switches_router.post("/release", response_model=KillSwitchResponse)
async def release_kill_switch(
    body: ReleaseKillSwitchRequest,
    service: ExecutionServiceDep,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> KillSwitchResponse:
    # Platform-wide release additionally requires CISO + oversight — enforced in domain.
    dto = await service.release_kill_switch(
        ReleaseKillSwitch(
            tenant_id=tenant_id,
            scope=body.scope,
            scope_ref=body.scope_ref,
            releasing_operator_id=principal_id,
            releasing_role=body.releasing_role,
            countersigning_operator_id=body.countersigning_operator_id,
            countersigning_role=body.countersigning_role,
        )
    )
    return KillSwitchResponse.model_validate(asdict(dto))


@kill_switches_router.post("/re-arm", response_model=KillSwitchResponse)
async def re_arm_kill_switch(
    body: ReArmKillSwitchRequest,
    service: ExecutionServiceDep,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> KillSwitchResponse:
    dto = await service.re_arm_kill_switch(
        ReArmKillSwitch(
            tenant_id=tenant_id,
            scope=body.scope,
            scope_ref=body.scope_ref,
            authority_operator_id=principal_id,
            authority_role=body.authority_role,
        )
    )
    return KillSwitchResponse.model_validate(asdict(dto))


@kill_switches_router.get("/{scope}/{scope_ref}", response_model=KillSwitchResponse)
async def get_kill_switch(
    scope: str,
    scope_ref: str,
    service: ExecutionServiceDep,
    tenant_id: TenantIdDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> KillSwitchResponse:
    from uuid import UUID

    dto = await service.get_kill_switch(
        GetKillSwitch(tenant_id=tenant_id, scope=scope, scope_ref=UUID(scope_ref))
    )
    return KillSwitchResponse.model_validate(asdict(dto))
