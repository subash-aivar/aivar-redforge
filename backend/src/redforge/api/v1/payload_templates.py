"""Payload Templates REST API endpoints.

Payload templates are platform-wide, not organization-scoped (see
attack_library.py's module docstring for the same rationale). Endpoints
require only authentication.
"""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_payload_template_service
from redforge.api.security import AuthenticatedPrincipal, get_current_principal
from redforge.application.payloads import PayloadTemplateDTO, PayloadTemplateService

router = APIRouter(prefix="/payload-templates", tags=["payload-templates"])


# ─── Request/Response Models ──────────────────────────────────────────────────


class CreatePayloadTemplateRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=150)
    description: str = ""
    category: str = Field(..., min_length=2)
    template: str = Field(..., min_length=1)
    variables: list[str] = Field(default_factory=list)
    severity: str = Field(
        default="medium", pattern=r"^(critical|high|medium|low|informational)$",
    )


class PayloadTemplateResponse(BaseModel):
    id: str
    name: str
    description: str
    category: str
    template: str
    variables: list[str]
    severity: str
    status: str
    created_at: str
    updated_at: str

    @classmethod
    def from_dto(cls, dto: PayloadTemplateDTO) -> "PayloadTemplateResponse":
        return cls(
            id=dto.id, name=dto.name, description=dto.description,
            category=dto.category, template=dto.template,
            variables=dto.variables, severity=dto.severity,
            status=dto.status, created_at=dto.created_at,
            updated_at=dto.updated_at,
        )


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", response_model=PayloadTemplateResponse, status_code=201)
async def create_payload_template(
    body: CreatePayloadTemplateRequest,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    service: PayloadTemplateService = Depends(get_payload_template_service),
) -> PayloadTemplateResponse:
    """Create a new payload template."""
    dto = await service.create(
        name=body.name, description=body.description,
        category=body.category, template=body.template,
        variables=body.variables, severity=body.severity,
    )
    return PayloadTemplateResponse.from_dto(dto)


@router.get("/{template_id}", response_model=PayloadTemplateResponse)
async def get_payload_template(
    template_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    service: PayloadTemplateService = Depends(get_payload_template_service),
) -> PayloadTemplateResponse:
    """Retrieve a payload template by ID."""
    dto = await service.get_by_id(template_id)
    return PayloadTemplateResponse.from_dto(dto)


@router.get("", response_model=list[PayloadTemplateResponse])
async def list_payload_templates(
    category: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    service: PayloadTemplateService = Depends(get_payload_template_service),
) -> list[PayloadTemplateResponse]:
    """List payload templates with filtering."""
    dtos = await service.list_templates(category, severity, limit, offset)
    return [PayloadTemplateResponse.from_dto(d) for d in dtos]


@router.delete("/{template_id}", status_code=204)
async def delete_payload_template(
    template_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    service: PayloadTemplateService = Depends(get_payload_template_service),
) -> None:
    """Delete a payload template."""
    await service.delete(template_id)
