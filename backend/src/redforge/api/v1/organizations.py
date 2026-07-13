"""Organization REST API endpoints."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_organization_service
from redforge.api.security import (
    AuthenticatedPrincipal,
    TenantContext,
    ensure_organization_match,
    get_current_principal,
    require_permission,
)
from redforge.application.organizations import OrganizationDTO, OrganizationService
from redforge.domain.identity.value_objects import Permission

router = APIRouter(prefix="/organizations")


# ─── Request/Response Models ──────────────────────────────────────────────────


class CreateOrganizationRequest(BaseModel):
    """Request body for creating an organization."""

    name: str = Field(..., min_length=2, max_length=100)
    slug: str = Field(..., min_length=2, max_length=63, pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$")
    plan: str = Field(default="free")


class RenameOrganizationRequest(BaseModel):
    """Request body for renaming an organization."""

    name: str = Field(..., min_length=2, max_length=100)


class SuspendOrganizationRequest(BaseModel):
    """Request body for suspending an organization."""

    reason: str = Field(default="", max_length=500)


class OrganizationResponse(BaseModel):
    """Response body for organization operations."""

    id: str
    name: str
    slug: str
    status: str
    plan: str
    created_at: str
    updated_at: str

    @classmethod
    def from_dto(cls, dto: OrganizationDTO) -> "OrganizationResponse":
        return cls(
            id=dto.id,
            name=dto.name,
            slug=dto.slug,
            status=dto.status,
            plan=dto.plan,
            created_at=dto.created_at,
            updated_at=dto.updated_at,
        )


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", response_model=OrganizationResponse, status_code=201)
async def create_organization(
    body: CreateOrganizationRequest,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    service: OrganizationService = Depends(get_organization_service),
) -> OrganizationResponse:
    """Register a new Organization.

    Requires only authentication (not an existing organization membership,
    since none can exist yet). The creating user is atomically granted
    an OWNER membership.
    """
    dto = await service.register(
        body.name, body.slug, body.plan, created_by_user_id=principal.user_id,
    )
    return OrganizationResponse.from_dto(dto)


@router.get("/{organization_id}", response_model=OrganizationResponse)
async def get_organization(
    organization_id: str,
    tenant: TenantContext = Depends(
        require_permission(Permission.ORG_READ, allow_when_suspended=True)
    ),
    service: OrganizationService = Depends(get_organization_service),
) -> OrganizationResponse:
    """Retrieve an Organization by ID."""
    ensure_organization_match(organization_id, tenant)
    dto = await service.get_by_id(organization_id)
    return OrganizationResponse.from_dto(dto)


@router.patch("/{organization_id}/rename", response_model=OrganizationResponse)
async def rename_organization(
    organization_id: str,
    body: RenameOrganizationRequest,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: OrganizationService = Depends(get_organization_service),
) -> OrganizationResponse:
    """Rename an Organization."""
    ensure_organization_match(organization_id, tenant)
    dto = await service.rename(organization_id, body.name, actor_user_id=tenant.user_id)
    return OrganizationResponse.from_dto(dto)


@router.post("/{organization_id}/deactivate", response_model=OrganizationResponse)
async def deactivate_organization(
    organization_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: OrganizationService = Depends(get_organization_service),
) -> OrganizationResponse:
    """Deactivate an Organization."""
    ensure_organization_match(organization_id, tenant)
    dto = await service.deactivate(organization_id, actor_user_id=tenant.user_id)
    return OrganizationResponse.from_dto(dto)


@router.post("/{organization_id}/activate", response_model=OrganizationResponse)
async def activate_organization(
    organization_id: str,
    tenant: TenantContext = Depends(
        require_permission(Permission.ORG_MANAGE, allow_when_suspended=True)
    ),
    service: OrganizationService = Depends(get_organization_service),
) -> OrganizationResponse:
    """Activate an Organization."""
    ensure_organization_match(organization_id, tenant)
    dto = await service.activate(organization_id, actor_user_id=tenant.user_id)
    return OrganizationResponse.from_dto(dto)


@router.post("/{organization_id}/suspend", response_model=OrganizationResponse)
async def suspend_organization(
    organization_id: str,
    body: SuspendOrganizationRequest,
    tenant: TenantContext = Depends(
        require_permission(Permission.ORG_MANAGE, allow_when_suspended=True)
    ),
    service: OrganizationService = Depends(get_organization_service),
) -> OrganizationResponse:
    """Suspend an Organization (policy violation, billing)."""
    ensure_organization_match(organization_id, tenant)
    dto = await service.suspend(organization_id, body.reason, actor_user_id=tenant.user_id)
    return OrganizationResponse.from_dto(dto)
