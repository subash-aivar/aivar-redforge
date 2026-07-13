"""Validation Policies REST API endpoints."""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_policy_service
from redforge.api.security import TenantContext, require_permission
from redforge.application.policies import PolicyDTO, PolicyService
from redforge.domain.identity.value_objects import Permission

router = APIRouter(prefix="/policies", tags=["policies"])


# ─── Request/Response Models ──────────────────────────────────────────────────


class CreatePolicyRequest(BaseModel):
    """organization_id is intentionally NOT a field — derived from the
    caller's verified TenantContext."""

    name: str = Field(..., min_length=3, max_length=150)
    description: str = ""
    attack_ids: list[str] = Field(default_factory=list)
    schedule_cron: str | None = None
    enabled: bool = True


class UpdatePolicyRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    attack_ids: list[str] | None = None
    schedule_cron: str | None = None
    enabled: bool | None = None


class PolicyResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str
    attack_ids: list[str]
    schedule_cron: str | None
    enabled: bool
    status: str
    created_at: str
    updated_at: str

    @classmethod
    def from_dto(cls, dto: PolicyDTO) -> "PolicyResponse":
        return cls(
            id=dto.id, organization_id=dto.organization_id,
            name=dto.name, description=dto.description,
            attack_ids=dto.attack_ids, schedule_cron=dto.schedule_cron,
            enabled=dto.enabled, status=dto.status,
            created_at=dto.created_at, updated_at=dto.updated_at,
        )


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", response_model=PolicyResponse, status_code=201)
async def create_policy(
    body: CreatePolicyRequest,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_MANAGE)),
    service: PolicyService = Depends(get_policy_service),
) -> PolicyResponse:
    """Create a new validation policy."""
    dto = await service.create(
        organization_id=tenant.organization_id, name=body.name,
        description=body.description, attack_ids=body.attack_ids,
        schedule_cron=body.schedule_cron, enabled=body.enabled,
    )
    return PolicyResponse.from_dto(dto)


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_READ)),
    service: PolicyService = Depends(get_policy_service),
) -> PolicyResponse:
    """Retrieve a validation policy by ID, scoped to the caller's organization."""
    dto = await service.get_by_id(policy_id, tenant.organization_id)
    return PolicyResponse.from_dto(dto)


@router.get("", response_model=list[PolicyResponse])
async def list_policies(
    enabled: bool | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_READ)),
    service: PolicyService = Depends(get_policy_service),
) -> list[PolicyResponse]:
    """List validation policies for the caller's organization."""
    dtos = await service.list_policies(tenant.organization_id, enabled, limit, offset)
    return [PolicyResponse.from_dto(d) for d in dtos]


@router.patch("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: str,
    body: UpdatePolicyRequest,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_MANAGE)),
    service: PolicyService = Depends(get_policy_service),
) -> PolicyResponse:
    """Update a validation policy, scoped to the caller's organization."""
    updates = body.model_dump(exclude_none=True)
    dto = await service.update(policy_id, tenant.organization_id, updates)
    return PolicyResponse.from_dto(dto)


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_MANAGE)),
    service: PolicyService = Depends(get_policy_service),
) -> None:
    """Delete a validation policy, scoped to the caller's organization."""
    await service.delete(policy_id, tenant.organization_id)
