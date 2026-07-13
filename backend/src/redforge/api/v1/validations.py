"""Validation Runs REST API endpoints."""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_validation_service
from redforge.api.security import TenantContext, require_permission
from redforge.application.validations import ValidationRunDTO, ValidationRunService
from redforge.domain.identity.value_objects import Permission

router = APIRouter(prefix="/validations", tags=["validations"])


# ─── Request/Response Models ──────────────────────────────────────────────────


class ScheduleValidationRequest(BaseModel):
    """organization_id is intentionally NOT a field — derived from the
    caller's verified TenantContext."""

    target_id: str
    trigger_type: str = Field(
        default="manual", pattern=r"^(manual|scheduled|ci_cd|policy|api)$",
    )
    policy_id: str | None = None


class ValidationRunResponse(BaseModel):
    id: str
    organization_id: str
    target_id: str
    status: str
    trigger_type: str
    policy_id: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    summary: dict[str, object] | None = None
    created_at: str
    updated_at: str

    @classmethod
    def from_dto(cls, dto: ValidationRunDTO) -> "ValidationRunResponse":
        return cls(
            id=dto.id, organization_id=dto.organization_id,
            target_id=dto.target_id, status=dto.status,
            trigger_type=dto.trigger_type, policy_id=dto.policy_id,
            started_at=dto.started_at, completed_at=dto.completed_at,
            summary=dto.summary, created_at=dto.created_at,
            updated_at=dto.updated_at,
        )


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", response_model=ValidationRunResponse, status_code=201)
async def schedule_validation(
    body: ScheduleValidationRequest,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_RUN)),
    service: ValidationRunService = Depends(get_validation_service),
) -> ValidationRunResponse:
    """Schedule a new validation run."""
    dto = await service.schedule(
        organization_id=tenant.organization_id,
        target_id=body.target_id,
        trigger_type=body.trigger_type,
        policy_id=body.policy_id,
    )
    return ValidationRunResponse.from_dto(dto)


@router.get("/{run_id}", response_model=ValidationRunResponse)
async def get_validation(
    run_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_READ)),
    service: ValidationRunService = Depends(get_validation_service),
) -> ValidationRunResponse:
    """Retrieve a validation run by ID, scoped to the caller's organization."""
    dto = await service.get_by_id(run_id, tenant.organization_id)
    return ValidationRunResponse.from_dto(dto)


@router.get("", response_model=list[ValidationRunResponse])
async def list_validations(
    target_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_READ)),
    service: ValidationRunService = Depends(get_validation_service),
) -> list[ValidationRunResponse]:
    """List validation runs for the caller's organization."""
    dtos = await service.list_runs(
        tenant.organization_id, target_id, status, limit, offset,
    )
    return [ValidationRunResponse.from_dto(d) for d in dtos]


@router.post("/{run_id}/cancel", response_model=ValidationRunResponse)
async def cancel_validation(
    run_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_MANAGE)),
    service: ValidationRunService = Depends(get_validation_service),
) -> ValidationRunResponse:
    """Cancel a scheduled or running validation, scoped to the caller's
    organization."""
    dto = await service.cancel(run_id, tenant.organization_id)
    return ValidationRunResponse.from_dto(dto)
