"""Continuous Validation Scheduler, Security Drift Detection & Revalidation
Engine REST API — M14.

Every route is tenant-scoped via TenantContext. organization_id is
NEVER accepted from the client. Policy lifecycle actions (create/
activate/pause/resume/disable) require VALIDATIONS_MANAGE; run-now
requires VALIDATIONS_RUN (symmetric with ad-hoc manual validation
creation); reads require VALIDATIONS_READ. No cron expression, no
schedule text box — cadence is a closed enum string
(hourly/every_6_hours/daily/weekly), never free text.

Route ordering matters: literal-path routes are registered before
`/{policy_id}` parametrized routes so they are not swallowed by the
path parameter.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from redforge.api.dependencies import (
    get_continuous_validation_policy_service,
    get_continuous_validation_processor,
    get_security_drift_service,
)
from redforge.api.security import TenantContext, require_permission
from redforge.application.continuous_validation.policy_service import (
    ContinuousValidationPolicyService,  # noqa: TC001
)
from redforge.application.continuous_validation.processor import (
    ContinuousValidationProcessor,  # noqa: TC001
)
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.continuous_validation.drift_service import (
        SecurityDriftEventDTO,
        SecurityDriftService,
    )
    from redforge.application.continuous_validation.policy_service import (
        ContinuousValidationPolicyDTO,
    )
    from redforge.application.validation_execution.execution_service import (
        ValidationExecutionDTO,
    )

router = APIRouter(prefix="/continuous-validation", tags=["continuous-validation"])


# ─── Request/Response Models ──────────────────────────────────────────────────


class CreatePolicyRequest(BaseModel):
    """organization_id and requester_user_id are intentionally NOT
    fields — derived from the caller's verified TenantContext. cadence
    is a closed enum string; there is no field for a cron expression or
    arbitrary schedule text anywhere in this bounded context."""

    target_id: str
    profile: str = Field(default="safe_active_baseline_v1")
    cadence: str = Field(default="daily")


class PolicyResponse(BaseModel):
    id: str
    organization_id: str
    target_id: str
    requester_user_id: str
    profile: str
    cadence: str
    lifecycle: str
    next_due_at: str | None
    last_scheduled_at: str | None
    created_at: str
    updated_at: str

    @classmethod
    def from_dto(cls, dto: ContinuousValidationPolicyDTO) -> PolicyResponse:
        return cls(
            id=dto.id, organization_id=dto.organization_id, target_id=dto.target_id,
            requester_user_id=dto.requester_user_id, profile=dto.profile, cadence=dto.cadence,
            lifecycle=dto.lifecycle, next_due_at=dto.next_due_at,
            last_scheduled_at=dto.last_scheduled_at,
            created_at=dto.created_at, updated_at=dto.updated_at,
        )


class DriftEventResponse(BaseModel):
    id: str
    organization_id: str
    continuous_policy_id: str
    execution_id: str
    category: str
    identity_key: str
    summary: str
    detail: dict[str, str]
    detected_at: str

    @classmethod
    def from_dto(cls, dto: SecurityDriftEventDTO) -> DriftEventResponse:
        return cls(
            id=dto.id, organization_id=dto.organization_id,
            continuous_policy_id=dto.continuous_policy_id, execution_id=dto.execution_id,
            category=dto.category, identity_key=dto.identity_key, summary=dto.summary,
            detail=dto.detail, detected_at=dto.detected_at,
        )


class RunNowResponse(BaseModel):
    """Deliberately minimal — the full execution record is already
    available via GET /validation-executions/{execution_id}; this
    response exists only to hand back the execution id and its trigger
    provenance without duplicating validation_executions.py's own
    response shape."""

    execution_id: str
    status: str
    trigger: str


def _run_now_response(dto: ValidationExecutionDTO) -> RunNowResponse:
    return RunNowResponse(execution_id=dto.id, status=dto.status, trigger=dto.trigger)


# ─── Policy endpoints ──────────────────────────────────────────────────────────


@router.post("/policies", response_model=PolicyResponse, status_code=201)
async def create_policy(
    body: CreatePolicyRequest,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_MANAGE)),
    service: ContinuousValidationPolicyService = Depends(
        get_continuous_validation_policy_service,
    ),
) -> PolicyResponse:
    """Create a new ContinuousValidationPolicy in DRAFT. Never
    immediately scheduled — activate() is the only path to ACTIVE."""
    dto = await service.create(
        organization_id=tenant.organization_id,
        target_id=body.target_id,
        requester_user_id=tenant.user_id,
        profile=body.profile,
        cadence=body.cadence,
    )
    return PolicyResponse.from_dto(dto)


@router.get("/policies", response_model=list[PolicyResponse])
async def list_policies(
    lifecycle: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_READ)),
    service: ContinuousValidationPolicyService = Depends(
        get_continuous_validation_policy_service,
    ),
) -> list[PolicyResponse]:
    dtos = await service.list_for_org(tenant.organization_id, lifecycle, limit, offset)
    return [PolicyResponse.from_dto(d) for d in dtos]


@router.get("/change-feed", response_model=list[DriftEventResponse])
async def get_change_feed(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_READ)),
    drift_service: SecurityDriftService = Depends(get_security_drift_service),
) -> list[DriftEventResponse]:
    """Org-wide live change feed across every policy, newest first."""
    dtos = await drift_service.list_for_org(tenant.organization_id, limit, offset)
    return [DriftEventResponse.from_dto(d) for d in dtos]


@router.get("/drift/{drift_event_id}", response_model=DriftEventResponse)
async def get_drift_detail(
    drift_event_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_READ)),
    drift_service: SecurityDriftService = Depends(get_security_drift_service),
) -> DriftEventResponse:
    from redforge.core.exceptions import NotFoundError

    dto = await drift_service.get(drift_event_id, tenant.organization_id)
    if dto is None:
        raise NotFoundError("SecurityDriftEvent", drift_event_id)
    return DriftEventResponse.from_dto(dto)


@router.get("/policies/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_READ)),
    service: ContinuousValidationPolicyService = Depends(
        get_continuous_validation_policy_service,
    ),
) -> PolicyResponse:
    dto = await service.get(tenant.organization_id, policy_id)
    return PolicyResponse.from_dto(dto)


@router.post("/policies/{policy_id}/activate", response_model=PolicyResponse)
async def activate_policy(
    policy_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_MANAGE)),
    service: ContinuousValidationPolicyService = Depends(
        get_continuous_validation_policy_service,
    ),
) -> PolicyResponse:
    dto = await service.activate(tenant.organization_id, policy_id)
    return PolicyResponse.from_dto(dto)


@router.post("/policies/{policy_id}/pause", response_model=PolicyResponse)
async def pause_policy(
    policy_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_MANAGE)),
    service: ContinuousValidationPolicyService = Depends(
        get_continuous_validation_policy_service,
    ),
) -> PolicyResponse:
    dto = await service.pause(tenant.organization_id, policy_id)
    return PolicyResponse.from_dto(dto)


@router.post("/policies/{policy_id}/resume", response_model=PolicyResponse)
async def resume_policy(
    policy_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_MANAGE)),
    service: ContinuousValidationPolicyService = Depends(
        get_continuous_validation_policy_service,
    ),
) -> PolicyResponse:
    dto = await service.resume(tenant.organization_id, policy_id)
    return PolicyResponse.from_dto(dto)


@router.post("/policies/{policy_id}/disable", response_model=PolicyResponse)
async def disable_policy(
    policy_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_MANAGE)),
    service: ContinuousValidationPolicyService = Depends(
        get_continuous_validation_policy_service,
    ),
) -> PolicyResponse:
    """DISABLED is terminal — see PolicyLifecycle's own docstring. This
    endpoint never silently reactivates a disabled policy; a repeat
    call against an already-disabled policy raises the same
    InvalidPolicyTransitionError as any other illegal transition."""
    dto = await service.disable(tenant.organization_id, policy_id)
    return PolicyResponse.from_dto(dto)


@router.post("/policies/{policy_id}/run-now", response_model=RunNowResponse)
async def run_policy_now(
    policy_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_RUN)),
    processor: ContinuousValidationProcessor = Depends(get_continuous_validation_processor),
) -> RunNowResponse:
    """Operator-triggered ON_DEMAND run — goes through the identical
    execute -> snapshot -> reconcile -> drift pipeline as a scheduled
    run, but is not tied to a due boundary and never advances
    next_due_at. A fresh M10 authorization check still applies (the
    same `create_and_run()` every other trigger path uses)."""
    dto = await processor.run_now(tenant.organization_id, policy_id)
    return _run_now_response(dto)


@router.get("/policies/{policy_id}/drift", response_model=list[DriftEventResponse])
async def list_policy_drift(
    policy_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_READ)),
    drift_service: SecurityDriftService = Depends(get_security_drift_service),
) -> list[DriftEventResponse]:
    dtos = await drift_service.list_for_policy(policy_id, tenant.organization_id, limit, offset)
    return [DriftEventResponse.from_dto(d) for d in dtos]
