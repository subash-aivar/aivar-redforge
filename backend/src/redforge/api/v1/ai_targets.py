"""AI Target REST API endpoints."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_ai_target_service, get_tenant_asset_service
from redforge.api.security import TenantContext, require_permission
from redforge.application.ai_targets import AITargetDTO, AITargetService
from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.domain.ai_targets.value_objects import Provider, TargetType
from redforge.domain.identity.value_objects import Permission

router = APIRouter(prefix="/targets")


# ─── Request/Response Models ──────────────────────────────────────────────────


class CreateTargetRequest(BaseModel):
    """Request body for registering an AI Target.

    organization_id is intentionally NOT a field here — it is derived
    from the caller's verified TenantContext, never from client input.
    """

    name: str = Field(..., min_length=2, max_length=150)
    description: str = Field(default="")
    target_type: TargetType
    provider: Provider
    endpoint: str
    auth_reference: str | None = None


class AITargetResponse(BaseModel):
    """Response body for AI Target operations."""

    id: str
    organization_id: str
    name: str
    description: str
    target_type: str
    provider: str
    endpoint: str
    status: str
    tags: list[str]
    created_at: str
    updated_at: str

    @classmethod
    def from_dto(cls, dto: AITargetDTO) -> "AITargetResponse":
        return cls(
            id=dto.id,
            organization_id=dto.organization_id,
            name=dto.name,
            description=dto.description,
            target_type=dto.target_type,
            provider=dto.provider,
            endpoint=dto.endpoint,
            status=dto.status,
            tags=dto.tags,
            created_at=dto.created_at,
            updated_at=dto.updated_at,
        )


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", response_model=AITargetResponse, status_code=201)
async def create_target(
    body: CreateTargetRequest,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_CREATE)),
    service: AITargetService = Depends(get_ai_target_service),
    asset_service: TenantAssetService = Depends(get_tenant_asset_service),
) -> AITargetResponse:
    """Register a new AI Target.

    After the target is transactionally created, resolves/creates its
    canonical asset (M3) as a best-effort secondary step — mirroring the
    existing "write campaign result after execution" pattern
    (api/v1/red_team.py's `_persist_campaign_result`). A failure here
    degrades inventory visibility but never rolls back or blocks target
    creation, and duplicate-retry-safe (get_or_create is race-safe on
    the tenant-scoped external_id unique index).
    """
    dto = await service.register(
        organization_id=tenant.organization_id,
        name=body.name,
        description=body.description,
        target_type=body.target_type,
        provider=body.provider,
        endpoint=body.endpoint,
        auth_reference=body.auth_reference,
    )
    try:
        await asset_service.get_or_create_for_target(
            organization_id=tenant.organization_id,
            target_id=dto.id,
            target_name=dto.name,
            target_type=dto.target_type,
        )
    except Exception:
        import logging

        logging.getLogger(__name__).warning(
            "target_asset_association_failed", exc_info=True,
        )
    return AITargetResponse.from_dto(dto)


@router.get("/{target_id}", response_model=AITargetResponse)
async def get_target(
    target_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: AITargetService = Depends(get_ai_target_service),
) -> AITargetResponse:
    """Retrieve an AI Target by ID, scoped to the caller's organization."""
    dto = await service.get_by_id(target_id, tenant.organization_id)
    return AITargetResponse.from_dto(dto)


@router.get("", response_model=list[AITargetResponse])
async def list_targets(
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: AITargetService = Depends(get_ai_target_service),
) -> list[AITargetResponse]:
    """List AI Targets for the caller's organization."""
    dtos = await service.list_by_organization(tenant.organization_id)
    return [AITargetResponse.from_dto(d) for d in dtos]


@router.post("/{target_id}/deactivate", response_model=AITargetResponse)
async def deactivate_target(
    target_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_MANAGE)),
    service: AITargetService = Depends(get_ai_target_service),
) -> AITargetResponse:
    """Deactivate an AI Target, scoped to the caller's organization."""
    dto = await service.deactivate(target_id, tenant.organization_id)
    return AITargetResponse.from_dto(dto)
