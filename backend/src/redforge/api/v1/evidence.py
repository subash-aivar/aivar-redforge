"""Evidence REST API endpoints."""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from redforge.api.dependencies import get_evidence_service
from redforge.api.security import TenantContext, require_permission
from redforge.application.evidence import EvidenceDTO, EvidenceService
from redforge.domain.identity.value_objects import Permission

router = APIRouter(prefix="/evidence", tags=["evidence"])


# ─── Response Models ──────────────────────────────────────────────────────────


class EvidenceResponse(BaseModel):
    id: str
    organization_id: str
    run_id: str
    target_id: str
    attack_id: str
    attack_type: str
    result: str
    confidence: float
    request_url: str
    response_status: int
    duration_ms: int
    finalized: bool
    created_at: str

    @classmethod
    def from_dto(cls, dto: EvidenceDTO) -> "EvidenceResponse":
        return cls(
            id=dto.id, organization_id=dto.organization_id,
            run_id=dto.run_id, target_id=dto.target_id,
            attack_id=dto.attack_id, attack_type=dto.attack_type,
            result=dto.result, confidence=dto.confidence,
            request_url=dto.request_url, response_status=dto.response_status,
            duration_ms=dto.duration_ms, finalized=dto.finalized,
            created_at=dto.created_at,
        )


class EvidenceListResponse(BaseModel):
    items: list[EvidenceResponse]
    total: int
    limit: int
    offset: int


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.get("/{evidence_id}", response_model=EvidenceResponse)
async def get_evidence(
    evidence_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.EVIDENCE_READ)),
    service: EvidenceService = Depends(get_evidence_service),
) -> EvidenceResponse:
    """Retrieve an evidence record by ID, scoped to the caller's organization."""
    dto = await service.get_by_id(evidence_id, tenant.organization_id)
    return EvidenceResponse.from_dto(dto)


@router.get("", response_model=EvidenceListResponse)
async def list_evidence(
    run_id: str = Query(...),
    target_id: str | None = Query(default=None),
    result: str | None = Query(
        default=None, pattern=r"^(pass|fail|error|inconclusive)$",
    ),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.EVIDENCE_READ)),
    service: EvidenceService = Depends(get_evidence_service),
) -> EvidenceListResponse:
    """List evidence records for a validation run owned by the caller's
    organization. A run_id belonging to another organization returns an
    empty list, not another tenant's evidence."""
    items, total = await service.list_by_run(
        run_id, tenant.organization_id, target_id, result, limit, offset,
    )
    return EvidenceListResponse(
        items=[EvidenceResponse.from_dto(d) for d in items],
        total=total, limit=limit, offset=offset,
    )
