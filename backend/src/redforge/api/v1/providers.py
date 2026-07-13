"""Providers REST API endpoints.

Provider configurations are organization-scoped (M2). Every endpoint
requires TenantContext (an authenticated caller with a selected
organization) and every read/mutation is scoped to
`tenant.organization_id` — never a client-supplied organization ID.
A different tenant's provider is treated identically to a nonexistent
one (404), so cross-tenant existence cannot even be confirmed by ID
guessing.

Credential security boundary (unchanged from Sprint 42-43):
  auth_ref is an environment-variable NAME (e.g. "OPENAI_API_KEY"), not the
  secret value. It is safe to store, persist, and return in API responses.
  The resolved secret is never returned by any endpoint.
"""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_provider_service
from redforge.api.security import TenantContext, get_tenant_context
from redforge.application.providers import ProviderDTO, ProviderService

router = APIRouter(prefix="/providers", tags=["providers"])


# ─── Request/Response Models ──────────────────────────────────────────────────


class RegisterProviderRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    provider_type: str = Field(
        ...,
        pattern=r"^(openai|anthropic|google|azure|aws|meta|mistral|custom)$",
    )
    base_url: str = ""
    models: list[str] = Field(default_factory=list)
    enabled: bool = True
    auth_ref: str = Field(
        default="",
        description=(
            "Server-side credential reference — an environment variable NAME "
            "(e.g. 'OPENAI_API_KEY'). The server resolves this to the actual "
            "secret at campaign launch time. This field is safe to store and "
            "return; it contains no secret material."
        ),
        max_length=200,
    )


class ProviderResponse(BaseModel):
    id: str
    name: str
    provider_type: str
    base_url: str
    models: list[str]
    enabled: bool
    status: str
    organization_id: str | None
    auth_ref: str
    credential_configured: bool
    created_at: str
    updated_at: str

    @classmethod
    def from_dto(cls, dto: ProviderDTO) -> "ProviderResponse":
        return cls(
            id=dto.id,
            name=dto.name,
            provider_type=dto.provider_type,
            base_url=dto.base_url,
            models=dto.models,
            enabled=dto.enabled,
            status=dto.status,
            organization_id=dto.organization_id,
            auth_ref=dto.auth_ref,
            # Indicates whether auth_ref is non-empty — does NOT resolve the credential
            credential_configured=bool(dto.auth_ref),
            created_at=dto.created_at,
            updated_at=dto.updated_at,
        )


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", response_model=ProviderResponse, status_code=201)
async def register_provider(
    body: RegisterProviderRequest,
    tenant: TenantContext = Depends(get_tenant_context),
    service: ProviderService = Depends(get_provider_service),
) -> ProviderResponse:
    """Register a new AI provider configuration owned by the caller's organization."""
    dto = await service.register(
        organization_id=tenant.organization_id,
        name=body.name, provider_type=body.provider_type,
        base_url=body.base_url, models=body.models,
        enabled=body.enabled, auth_ref=body.auth_ref,
    )
    return ProviderResponse.from_dto(dto)


@router.get("/{provider_id}", response_model=ProviderResponse)
async def get_provider(
    provider_id: str,
    tenant: TenantContext = Depends(get_tenant_context),
    service: ProviderService = Depends(get_provider_service),
) -> ProviderResponse:
    """Retrieve a provider by ID. 404s for a provider owned by another
    organization, identically to a nonexistent ID. Never returns the
    resolved credential value.
    """
    dto = await service.get_by_id(provider_id, tenant.organization_id)
    return ProviderResponse.from_dto(dto)


@router.get("", response_model=list[ProviderResponse])
async def list_providers(
    provider_type: str | None = Query(default=None),
    enabled: bool | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(get_tenant_context),
    service: ProviderService = Depends(get_provider_service),
) -> list[ProviderResponse]:
    """List providers owned by the caller's organization only. Never
    returns resolved credential values.
    """
    dtos = await service.list_providers(
        tenant.organization_id, provider_type, enabled, limit, offset,
    )
    return [ProviderResponse.from_dto(d) for d in dtos]


@router.patch("/{provider_id}/disable", response_model=ProviderResponse)
async def disable_provider(
    provider_id: str,
    tenant: TenantContext = Depends(get_tenant_context),
    service: ProviderService = Depends(get_provider_service),
) -> ProviderResponse:
    """Disable a provider owned by the caller's organization."""
    dto = await service.disable(provider_id, tenant.organization_id)
    return ProviderResponse.from_dto(dto)


@router.patch("/{provider_id}/enable", response_model=ProviderResponse)
async def enable_provider(
    provider_id: str,
    tenant: TenantContext = Depends(get_tenant_context),
    service: ProviderService = Depends(get_provider_service),
) -> ProviderResponse:
    """Enable a previously disabled provider owned by the caller's organization."""
    dto = await service.enable(provider_id, tenant.organization_id)
    return ProviderResponse.from_dto(dto)
