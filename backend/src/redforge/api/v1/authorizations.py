"""Security Authorization & Execution Policy REST API — M10.

Every route is tenant-scoped via TenantContext (see api/security.py).
organization_id is NEVER accepted from the client — it always comes
from the caller's verified token. Clients cannot set ACTIVE directly,
forge an approver identity, forge a policy decision, or forge a reason
code — every one of those is server-computed here or in the
application layer.

Route ordering matters: literal-path routes (/evaluate, /decisions)
are registered BEFORE the /{authorization_id} parametrized routes so
they are not swallowed by the path parameter.
"""

from __future__ import annotations

from datetime import datetime  # noqa: TC003 — Pydantic resolves this at runtime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from redforge.api.dependencies import (
    get_execution_policy_service,
    get_security_authorization_service,
)
from redforge.api.security import TenantContext, require_permission
from redforge.application.authorization import (
    ApprovalDTO,
    AuthorizationDTO,
    ExecutionPolicyResultDTO,
    ScopeEntryDTO,
    SecurityAuthorizationService,
)

# FastAPI/Pydantic resolve annotations at runtime despite `from __future__
# import annotations` — these two imports must stay real imports, not
# TYPE_CHECKING-only (ruff's TC001/TC003 heuristics don't know that).
from redforge.application.authorization.execution_policy_service import (
    ExecutionPolicyService,  # noqa: TC001
)
from redforge.domain.identity.value_objects import Permission

router = APIRouter(prefix="/authorizations", tags=["authorizations"])


# ─── Request/Response Models ──────────────────────────────────────────────────


class ScopeEntryRequest(BaseModel):
    entity_type: str = Field(..., description="'ai_target' or 'ai_asset'")
    entity_id: str


class ScopeEntryResponse(BaseModel):
    entity_type: str
    entity_id: str

    @classmethod
    def from_dto(cls, dto: ScopeEntryDTO) -> ScopeEntryResponse:
        return cls(entity_type=dto.entity_type, entity_id=dto.entity_id)


class CreateAuthorizationRequest(BaseModel):
    """organization_id and requester_user_id are intentionally NOT
    fields — derived from the caller's verified TenantContext. A client
    can never create anything other than DRAFT."""

    action_classes: list[str] = Field(..., min_length=1)
    scope: list[ScopeEntryRequest] = Field(..., min_length=1)
    valid_from: datetime
    valid_until: datetime


class RejectRequest(BaseModel):
    reason: str = Field(default="", max_length=500)


class RevokeRequest(BaseModel):
    reason: str = Field(default="", max_length=500)


class ApprovalResponse(BaseModel):
    id: str
    authorization_id: str
    requester_user_id: str
    approver_user_id: str | None
    decision: str | None
    requested_at: str
    decided_at: str | None
    reason: str

    @classmethod
    def from_dto(cls, dto: ApprovalDTO) -> ApprovalResponse:
        return cls(
            id=dto.id, authorization_id=dto.authorization_id,
            requester_user_id=dto.requester_user_id, approver_user_id=dto.approver_user_id,
            decision=dto.decision, requested_at=dto.requested_at, decided_at=dto.decided_at,
            reason=dto.reason,
        )


class AuthorizationResponse(BaseModel):
    id: str
    organization_id: str
    requester_user_id: str
    status: str
    action_classes: list[str]
    scope: list[ScopeEntryResponse]
    valid_from: str
    valid_until: str
    created_at: str
    updated_at: str
    approval: ApprovalResponse | None = None

    @classmethod
    def from_dto(
        cls, dto: AuthorizationDTO, approval: ApprovalDTO | None = None,
    ) -> AuthorizationResponse:
        return cls(
            id=dto.id, organization_id=dto.organization_id,
            requester_user_id=dto.requester_user_id, status=dto.status,
            action_classes=dto.action_classes,
            scope=[ScopeEntryResponse.from_dto(s) for s in dto.scope],
            valid_from=dto.valid_from, valid_until=dto.valid_until,
            created_at=dto.created_at, updated_at=dto.updated_at,
            approval=ApprovalResponse.from_dto(approval) if approval is not None else None,
        )


class EvaluateRequest(BaseModel):
    action_class: str
    entities: list[ScopeEntryRequest] = Field(default_factory=list)


class EvaluateResponse(BaseModel):
    decision: str
    reason_code: str
    decision_id: str

    @classmethod
    def from_dto(cls, dto: ExecutionPolicyResultDTO) -> EvaluateResponse:
        return cls(decision=dto.decision, reason_code=dto.reason_code, decision_id=dto.decision_id)


class DecisionHistoryEntry(BaseModel):
    id: str
    authorization_id: str | None
    actor_user_id: str
    action_class: str | None
    entity_refs: list[dict[str, str]]
    decision: str
    reason_code: str
    evaluated_at: str


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", response_model=AuthorizationResponse, status_code=201)
async def create_authorization(
    body: CreateAuthorizationRequest,
    tenant: TenantContext = Depends(require_permission(Permission.AUTHORIZATIONS_CREATE)),
    service: SecurityAuthorizationService = Depends(get_security_authorization_service),
) -> AuthorizationResponse:
    """Create a new DRAFT authorization. Always DRAFT — a client cannot
    create anything else."""
    dto = await service.create(
        organization_id=tenant.organization_id,
        requester_user_id=tenant.user_id,
        action_classes=body.action_classes,
        scope=[ScopeEntryDTO(entity_type=s.entity_type, entity_id=s.entity_id) for s in body.scope],
        valid_from=body.valid_from,
        valid_until=body.valid_until,
    )
    return AuthorizationResponse.from_dto(dto)


@router.get("", response_model=list[AuthorizationResponse])
async def list_authorizations(
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.AUTHORIZATIONS_READ)),
    service: SecurityAuthorizationService = Depends(get_security_authorization_service),
) -> list[AuthorizationResponse]:
    """List authorizations for the caller's organization, newest first."""
    dtos = await service.list_by_organization(tenant.organization_id, status, limit, offset)
    return [AuthorizationResponse.from_dto(d) for d in dtos]


@router.get("/summary", response_model=dict[str, int])
async def get_authorization_summary(
    tenant: TenantContext = Depends(require_permission(Permission.AUTHORIZATIONS_READ)),
    service: SecurityAuthorizationService = Depends(get_security_authorization_service),
) -> dict[str, int]:
    """Backend-derived lifecycle counts for the caller's organization —
    never a client-side fabricated trend."""
    return await service.summary(tenant.organization_id)


@router.post("/evaluate", response_model=EvaluateResponse)
async def evaluate_policy(
    body: EvaluateRequest,
    tenant: TenantContext = Depends(require_permission(Permission.AUTHORIZATIONS_EVALUATE)),
    policy_service: ExecutionPolicyService = Depends(get_execution_policy_service),
) -> EvaluateResponse:
    """Trusted evaluation endpoint for proving M10. Never executes
    anything — returns ALLOW / DENY / APPROVAL_REQUIRED plus a
    server-controlled reason code and an auditable decision_id."""
    result = await policy_service.evaluate(
        organization_id=tenant.organization_id,
        actor_user_id=tenant.user_id,
        action_class=body.action_class,
        entity_refs=[(e.entity_type, e.entity_id) for e in body.entities],
    )
    return EvaluateResponse.from_dto(result)


@router.get("/decisions", response_model=list[DecisionHistoryEntry])
async def list_decisions(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.AUTHORIZATIONS_READ)),
    policy_service: ExecutionPolicyService = Depends(get_execution_policy_service),
) -> list[DecisionHistoryEntry]:
    """Tenant-scoped policy decision audit history."""
    rows = await policy_service.list_decisions(tenant.organization_id, limit, offset)
    return [DecisionHistoryEntry.model_validate(row) for row in rows]


@router.get("/{authorization_id}", response_model=AuthorizationResponse)
async def get_authorization(
    authorization_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.AUTHORIZATIONS_READ)),
    service: SecurityAuthorizationService = Depends(get_security_authorization_service),
) -> AuthorizationResponse:
    """Retrieve one authorization, scoped to the caller's organization.
    A guessed foreign-tenant id is indistinguishable from "does not
    exist" — both raise NotFoundError -> 404."""
    dto = await service.get_by_id(tenant.organization_id, authorization_id)
    approval = await service.get_approval(tenant.organization_id, authorization_id)
    return AuthorizationResponse.from_dto(dto, approval)


@router.post("/{authorization_id}/submit", response_model=AuthorizationResponse)
async def submit_authorization(
    authorization_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.AUTHORIZATIONS_CREATE)),
    service: SecurityAuthorizationService = Depends(get_security_authorization_service),
) -> AuthorizationResponse:
    """DRAFT -> PENDING_APPROVAL."""
    dto = await service.submit_for_approval(
        tenant.organization_id, authorization_id, tenant.user_id,
    )
    approval = await service.get_approval(tenant.organization_id, authorization_id)
    return AuthorizationResponse.from_dto(dto, approval)


@router.post("/{authorization_id}/approve", response_model=AuthorizationResponse)
async def approve_authorization(
    authorization_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.AUTHORIZATIONS_APPROVE)),
    service: SecurityAuthorizationService = Depends(get_security_authorization_service),
) -> AuthorizationResponse:
    """PENDING_APPROVAL -> ACTIVE. The requester can never approve their
    own authorization — enforced unconditionally in the domain layer,
    regardless of role."""
    dto = await service.approve(
        tenant.organization_id, authorization_id, tenant.user_id, tenant.permissions,
    )
    approval = await service.get_approval(tenant.organization_id, authorization_id)
    return AuthorizationResponse.from_dto(dto, approval)


@router.post("/{authorization_id}/reject", response_model=AuthorizationResponse)
async def reject_authorization(
    authorization_id: str,
    body: RejectRequest = RejectRequest(),
    tenant: TenantContext = Depends(require_permission(Permission.AUTHORIZATIONS_APPROVE)),
    service: SecurityAuthorizationService = Depends(get_security_authorization_service),
) -> AuthorizationResponse:
    """PENDING_APPROVAL -> REJECTED. Terminal."""
    dto = await service.reject(
        tenant.organization_id, authorization_id, tenant.user_id, tenant.permissions, body.reason,
    )
    approval = await service.get_approval(tenant.organization_id, authorization_id)
    return AuthorizationResponse.from_dto(dto, approval)


@router.post("/{authorization_id}/revoke", response_model=AuthorizationResponse)
async def revoke_authorization(
    authorization_id: str,
    body: RevokeRequest = RevokeRequest(),
    tenant: TenantContext = Depends(require_permission(Permission.AUTHORIZATIONS_CREATE)),
    service: SecurityAuthorizationService = Depends(get_security_authorization_service),
) -> AuthorizationResponse:
    """ACTIVE -> REVOKED. Terminal. The next evaluate() call for this
    authorization denies immediately (time-of-use enforcement)."""
    dto = await service.revoke(
        tenant.organization_id, authorization_id, tenant.user_id, body.reason,
    )
    approval = await service.get_approval(tenant.organization_id, authorization_id)
    return AuthorizationResponse.from_dto(dto, approval)
