from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from automated_action.api.dependencies import get_container, roles_header, tenant_id_header
from automated_action.application.commands.automation_commands import (
    AuthorizeAutomationStep,
    CancelExecution,
    RequestRollback,
    TriggerPlaybookExecution,
)
from automated_action.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
)
from automated_action.domain.exceptions.domain_exceptions import AutomationDomainError
from automated_action.infrastructure.container import AutomatedActionContainer

router = APIRouter(tags=["automated-action"])


def _map(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, AutomationDomainError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


class TriggerBody(BaseModel):
    playbook_id: UUID
    version_number: int
    source_context: str = "MANUAL"
    source_event_type: str = "manual"
    source_event_id: str
    operator_id: str = "api"


class AuthorizeBody(BaseModel):
    escalation_id: UUID
    authorizer_id: str
    notes: str | None = None


class RollbackBody(BaseModel):
    record_id: UUID
    initiated_by: str = "api"


class CancelBody(BaseModel):
    cancelled_by: str = "api"
    reason: str = "cancelled"


@router.get("/executions")
async def list_executions(
    status_filter: str | None = None,
    playbook_id_filter: str | None = None,
    page: int = 1,
    page_size: int = 50,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutomatedActionContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        rows = await container.app.list_executions(
            tenant_id,
            roles,
            status_filter=status_filter,
            playbook_id_filter=playbook_id_filter,
            page=page,
            page_size=page_size,
        )
        return [asdict(r) for r in rows]
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/executions", status_code=201)
async def trigger(
    body: TriggerBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutomatedActionContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.trigger(
            TriggerPlaybookExecution(
                tenant_id,
                body.playbook_id,
                body.version_number,
                body.source_context,
                body.source_event_type,
                body.source_event_id,
                body.operator_id,
                roles,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/executions/{execution_id}")
async def get_execution(
    execution_id: UUID,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutomatedActionContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return asdict(await container.app.get(tenant_id, execution_id, roles))
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/executions/{execution_id}/action-records")
async def action_records(
    execution_id: UUID,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutomatedActionContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        rows = await container.app.action_records(tenant_id, execution_id, roles)
        return [asdict(r) for r in rows]
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/executions/{execution_id}/authorize-step")
async def authorize_step(
    execution_id: UUID,
    body: AuthorizeBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutomatedActionContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.authorize_step(
            AuthorizeAutomationStep(
                tenant_id,
                execution_id,
                body.escalation_id,
                body.authorizer_id,
                roles,
                body.notes,
                roles,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/executions/{execution_id}/rollback")
async def rollback(
    execution_id: UUID,
    body: RollbackBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutomatedActionContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.request_rollback(
            RequestRollback(tenant_id, execution_id, body.record_id, body.initiated_by, roles)
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/executions/{execution_id}/cancel")
async def cancel(
    execution_id: UUID,
    body: CancelBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutomatedActionContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.cancel(
            CancelExecution(tenant_id, execution_id, body.cancelled_by, body.reason, roles)
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/executions/pending/escalations")
async def pending_escalations(
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutomatedActionContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        rows = await container.app.pending_escalations(tenant_id, roles)
        return [asdict(r) for r in rows]
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/automation/metrics")
async def metrics(container: AutomatedActionContainer = Depends(get_container)) -> dict[str, Any]:
    return {
        "counters": container.app.metrics.counters,
        "dead_letters": len(container.retry_worker.dead_letters),
    }
