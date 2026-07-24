from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from playbook.api.dependencies import get_container, roles_header, tenant_id_header
from playbook.application.commands.playbook_commands import (
    ActivateKillSwitch,
    ApprovePlaybook,
    CreatePlaybook,
    DeprecatePlaybook,
    PublishPlaybookVersion,
    ResetKillSwitch,
    RunPlaybookDryRun,
    SubmitPlaybookForApproval,
    UpdateAutomationPolicy,
)
from playbook.application.exceptions import ApplicationForbiddenError, ApplicationNotFoundError
from playbook.domain.exceptions.domain_exceptions import PlaybookDomainError
from playbook.domain.value_objects.identifiers import TenantId
from playbook.infrastructure.container import PlaybookContainer

router = APIRouter(tags=["playbook"])


def _map(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, PlaybookDomainError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


class CreateBody(BaseModel):
    name: str
    description: str
    created_by: str = "api"


class PublishBody(BaseModel):
    action_steps: list[dict[str, object]]
    trigger_configs: list[dict[str, object]] = Field(default_factory=list)
    published_by: str = "api"


class SubmitBody(BaseModel):
    version_number: int
    submitted_by: str = "api"


class ApproveBody(BaseModel):
    version_number: int
    approved_by: str
    approved_by_role: str


class DeprecateBody(BaseModel):
    deprecated_by: str
    reason: str


class DryRunBody(BaseModel):
    version_id: UUID
    executed_by: str = "api"


class KillSwitchBody(BaseModel):
    activated_by: str
    reason: str


class PolicyBody(BaseModel):
    updated_by: str = "api"
    max_concurrent_executions: int | None = None
    max_actions_per_hour: int | None = None


@router.get("/health/automation")
async def automation_health(
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: PlaybookContainer = Depends(get_container),
) -> dict[str, Any]:
    policy = await container.app.get_policy(tenant_id, roles or ("playbook:analyst",))
    return {
        "status": "ok",
        "context": "playbook",
        "kill_switch_state": policy.kill_switch_state,
        "metrics": container.metrics.snapshot(),
        "scheduler": container.scheduler.tick_all(),
    }


@router.get("/playbooks")
async def list_playbooks(
    status_filter: str | None = None,
    page: int = 1,
    page_size: int = 50,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: PlaybookContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        rows = await container.app.list_playbooks(
            tenant_id, roles, status_filter=status_filter, page=page, page_size=page_size
        )
        return [asdict(r) for r in rows]
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/playbooks", status_code=201)
async def create_playbook(
    body: CreateBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: PlaybookContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.create(
            CreatePlaybook(tenant_id, body.name, body.description, body.created_by, roles)
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/playbooks/{playbook_id}")
async def get_playbook(
    playbook_id: UUID,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: PlaybookContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return asdict(await container.app.get_playbook(tenant_id, playbook_id, roles))
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/playbooks/{playbook_id}/versions", status_code=201)
async def publish_version(
    playbook_id: UUID,
    body: PublishBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: PlaybookContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.publish_version(
            PublishPlaybookVersion(
                tenant_id,
                playbook_id,
                body.action_steps,
                body.trigger_configs,
                body.published_by,
                roles,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/playbooks/{playbook_id}/submit-for-approval")
async def submit(
    playbook_id: UUID,
    body: SubmitBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: PlaybookContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.submit_for_approval(
            SubmitPlaybookForApproval(
                tenant_id, playbook_id, body.version_number, body.submitted_by, roles
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/playbooks/{playbook_id}/approve")
async def approve(
    playbook_id: UUID,
    body: ApproveBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: PlaybookContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.approve(
            ApprovePlaybook(
                tenant_id,
                playbook_id,
                body.version_number,
                body.approved_by,
                body.approved_by_role,
                roles,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/playbooks/{playbook_id}/deprecate")
async def deprecate(
    playbook_id: UUID,
    body: DeprecateBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: PlaybookContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.deprecate(
            DeprecatePlaybook(tenant_id, playbook_id, body.deprecated_by, body.reason, roles)
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/playbooks/{playbook_id}/dry-run")
async def dry_run(
    playbook_id: UUID,
    body: DryRunBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: PlaybookContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.dry_run(
            RunPlaybookDryRun(tenant_id, playbook_id, body.version_id, body.executed_by, roles)
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/automation-policy")
async def get_policy(
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: PlaybookContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return asdict(await container.app.get_policy(tenant_id, roles))
    except Exception as exc:
        raise _map(exc) from exc


@router.patch("/automation-policy")
async def update_policy(
    body: PolicyBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: PlaybookContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.update_policy(
            UpdateAutomationPolicy(
                tenant_id,
                body.updated_by,
                roles,
                body.max_concurrent_executions,
                body.max_actions_per_hour,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/automation-policy/kill-switch")
async def activate_kill_switch(
    body: KillSwitchBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: PlaybookContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.activate_kill_switch(
            ActivateKillSwitch(tenant_id, body.activated_by, body.reason, roles)
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.delete("/automation-policy/kill-switch")
async def reset_kill_switch(
    reset_by: str = "api",
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: PlaybookContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.reset_kill_switch(ResetKillSwitch(tenant_id, reset_by, roles))
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc
