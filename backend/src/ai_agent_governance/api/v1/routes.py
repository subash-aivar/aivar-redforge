from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from ai_agent_governance.api.dependencies import (
    get_actor_roles,
    get_container,
    get_tenant_id,
)
from ai_agent_governance.api.schemas.governance_schemas import (
    AddActionRequest,
    ApproveEnvelopeRequest,
    DraftEnvelopeRequest,
    ReportActionRequest,
    ReviewDeviationRequest,
    ReviseEnvelopeRequest,
    SuspendEnvelopeRequest,
)
from ai_agent_governance.application.commands.governance_commands import (
    AddAuthorizedActionCommand,
    ApproveEnvelopeCommand,
    DraftEnvelopeCommand,
    ReportAgentActionCommand,
    ReviewDeviationCommand,
    ReviseEnvelopeCommand,
    SuspendEnvelopeCommand,
)
from ai_agent_governance.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from ai_agent_governance.infrastructure.container import AgentGovernanceContainer

router = APIRouter(prefix="/ai-agent-governance", tags=["ai-agent-governance"])


def _map_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationValidationError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail=str(exc))


@router.post("/envelopes")
async def draft_envelope(
    body: DraftEnvelopeRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AgentGovernanceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.envelope_service.draft(
            DraftEnvelopeCommand(
                tenant_id=tenant_id,
                asset_id=body.asset_id,
                max_data_sensitivity=body.max_data_sensitivity,
                requires_human_approval_for=tuple(body.requires_human_approval_for),
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/envelopes/{envelope_id}/actions")
async def add_action(
    envelope_id: UUID,
    body: AddActionRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AgentGovernanceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.envelope_service.add_action(
            AddAuthorizedActionCommand(
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                category=body.category,
                description=body.description,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/envelopes/{envelope_id}/approve")
async def approve_envelope(
    envelope_id: UUID,
    body: ApproveEnvelopeRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AgentGovernanceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.envelope_service.approve(
            ApproveEnvelopeCommand(
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                approver_id=body.approver_id,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/envelopes/{envelope_id}/revise")
async def revise_envelope(
    envelope_id: UUID,
    body: ReviseEnvelopeRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AgentGovernanceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        new_actions = tuple((a[0], a[1] if len(a) > 1 else "") for a in body.new_actions)
        dto = await container.envelope_service.revise(
            ReviseEnvelopeCommand(
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                new_actions=new_actions,
                remove_human_approval_for=tuple(body.remove_human_approval_for),
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/envelopes/{envelope_id}/suspend")
async def suspend_envelope(
    envelope_id: UUID,
    body: SuspendEnvelopeRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AgentGovernanceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.envelope_service.suspend(
            SuspendEnvelopeCommand(
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                reason=body.reason,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/actions/report")
async def report_action(
    body: ReportActionRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AgentGovernanceContainer = Depends(get_container),
) -> dict[str, Any]:
    """Idempotent agent action report — batch-friendly transport contract."""
    try:
        dto = await container.deviation_service.report_action(
            ReportAgentActionCommand(
                tenant_id=tenant_id,
                asset_id=body.asset_id,
                action_category=body.action_category,
                resource=body.resource,
                data_sensitivity=body.data_sensitivity,
                human_approval_present=body.human_approval_present,
                occurred_at=body.occurred_at,
                idempotency_key=body.idempotency_key,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/deviations/{deviation_id}/review")
async def review_deviation(
    deviation_id: UUID,
    body: ReviewDeviationRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AgentGovernanceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.deviation_service.review(
            ReviewDeviationCommand(
                tenant_id=tenant_id,
                deviation_id=deviation_id,
                decision=body.decision,
                notes=body.notes,
                linked_revision_event_id=body.linked_revision_event_id,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.get("/envelopes/{envelope_id}/advisories")
async def get_advisories(
    envelope_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AgentGovernanceContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    from ai_agent_governance.application.queries.governance_queries import (
        GetEnvelopeAdvisoriesQuery,
    )

    try:
        items = await container.query_handler.get_advisories(
            GetEnvelopeAdvisoriesQuery(
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return [asdict(i) for i in items]
