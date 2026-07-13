"""Risk Incidents REST API endpoints."""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_finding_service, get_risk_engine
from redforge.api.security import TenantContext, require_permission
from redforge.application.findings import FindingService
from redforge.application.risk_engine import (
    FindingInput,
    RiskCorrelationEngine,
    RiskIncident,
)
from redforge.domain.identity.value_objects import Permission

router = APIRouter(prefix="/risk-incidents", tags=["risk-incidents"])


# ─── Request/Response Models ──────────────────────────────────────────────────


class CorrelateRiskRequest(BaseModel):
    """organization_id is intentionally NOT a field — derived from the
    caller's verified TenantContext."""

    finding_ids: list[str] = Field(..., min_length=1)
    chain_ids: list[str] = Field(default_factory=list)
    validation_run_ids: list[str] = Field(default_factory=list)


class RiskIncidentResponse(BaseModel):
    incident_id: str
    organization_id: str
    risk_score: float
    priority: str
    status: str
    title: str
    executive_summary: str
    recommended_actions: list[str]
    affected_targets: list[str]
    finding_ids: list[str]
    attack_types: list[str]
    trend: str
    created_at: str
    updated_at: str

    @classmethod
    def from_incident(cls, inc: RiskIncident) -> "RiskIncidentResponse":
        return cls(
            incident_id=inc.incident_id,
            organization_id=inc.organization_id,
            risk_score=inc.risk_score.overall,
            priority=inc.priority.value,
            status=inc.status.value,
            title=inc.title,
            executive_summary=inc.executive_summary,
            recommended_actions=inc.recommended_actions,
            affected_targets=inc.affected_targets,
            finding_ids=inc.finding_ids,
            attack_types=inc.attack_types,
            trend=inc.trend.value,
            created_at=inc.created_at.isoformat(),
            updated_at=inc.updated_at.isoformat(),
        )


class RiskIncidentListResponse(BaseModel):
    items: list[RiskIncidentResponse]
    total: int
    limit: int
    offset: int


class AcknowledgeRequest(BaseModel):
    acknowledged_by: str = Field(..., min_length=1)
    notes: str = ""


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post("/correlate", response_model=list[RiskIncidentResponse], status_code=201)
async def correlate_risk(
    body: CorrelateRiskRequest,
    tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
    engine: RiskCorrelationEngine = Depends(get_risk_engine),
    finding_service: FindingService = Depends(get_finding_service),
) -> list[RiskIncidentResponse]:
    """Correlate findings into risk incidents using the Risk Correlation Engine.

    Every finding_id is resolved through the caller's organization scope
    (FindingService.get_by_id) — a finding_id belonging to another
    organization is silently skipped, not correlated into this response.
    """
    finding_inputs: list[FindingInput] = []
    for fid in body.finding_ids:
        try:
            dto = await finding_service.get_by_id(fid, tenant.organization_id)
        except Exception:
            continue
        finding_inputs.append(FindingInput(
            finding_id=dto.id,
            target_id=dto.target_id,
            organization_id=dto.organization_id,
            run_id=dto.run_id,
            severity=dto.severity,
            risk_score=dto.risk_score,
            title=dto.title,
            evidence_ids=dto.evidence_ids,
        ))

    incidents = engine.correlate(finding_inputs)
    return [RiskIncidentResponse.from_incident(i) for i in incidents]


@router.get("/{incident_id}", response_model=RiskIncidentResponse)
async def get_risk_incident(
    incident_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
    engine: RiskCorrelationEngine = Depends(get_risk_engine),
) -> RiskIncidentResponse:
    """Retrieve a risk incident by ID.

    Note: Incidents are currently computed on-demand. A persistence
    layer will be added for incident lifecycle management.
    """
    from redforge.core.exceptions import NotFoundError
    raise NotFoundError("RiskIncident", incident_id)


@router.get("", response_model=RiskIncidentListResponse)
async def list_risk_incidents(
    priority: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> RiskIncidentListResponse:
    """List risk incidents with filtering.

    Note: Returns empty until incident persistence is implemented.
    Use POST /correlate to generate incidents on-demand.
    """
    return RiskIncidentListResponse(items=[], total=0, limit=limit, offset=offset)
