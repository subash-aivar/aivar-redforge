"""Security Operations Command Center REST API — M18.

Read-oriented, tenant-scoped command-center aggregates that COMPOSE
existing truth: the deterministic posture score + high-risk assets +
inventory (overview), deterministic UEBA/HBA/NBA behavior signals, the
six external-telemetry integration boundaries (NOT_CONFIGURED until a
provider is wired), and explicit admin-authored network-zone / DMZ
classification.

organization_id is NEVER accepted from the client — always derived from
the verified TenantContext. Reads are gated by SECURITY_OPERATIONS_READ
(the read-only command-center permission held by all tenant roles) or
NETWORK_SECURITY_READ for network-domain reads; administrative writes
(zone assignment, integration registration) require a management
permission and are audited.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from redforge.api.dependencies import (
    get_behavior_analytics_service,
    get_command_overview_service,
    get_integration_status_service,
    get_network_zone_service,
)
from redforge.api.security import TenantContext, require_permission
from redforge.application.command_center.behavior_service import (
    BehaviorAnalyticsService,
)
from redforge.application.command_center.integration_service import (
    IntegrationStatusService,
)
from redforge.application.command_center.overview_service import (
    CommandOverviewService,
)
from redforge.application.command_center.zone_service import (
    NetworkZoneService,
)
from redforge.domain.command_center.value_objects import BehaviorDomain
from redforge.domain.identity.value_objects import Permission
from redforge.domain.security_operations.value_objects import BoundedPeriod

if TYPE_CHECKING:
    from redforge.application.command_center.overview_service import CommandOverviewDTO

router = APIRouter(prefix="/command-center", tags=["command-center"])


# ─── Response models ───────────────────────────────────────────────────────


class PostureContributionResponse(BaseModel):
    factor: str
    count: int
    weight: int
    deduction: int


class HighRiskAssetResponse(BaseModel):
    asset_id: str
    asset_name: str
    asset_type: str
    active_condition_count: int


class CommandOverviewResponse(BaseModel):
    posture_score: int
    posture_band: str
    posture_formula_version: str
    posture_total_deduction: int
    posture_contributions: list[PostureContributionResponse]
    active_condition_count: int
    active_conditions_by_severity: dict[str, int]
    active_correlation_count: int
    high_risk_assets: list[HighRiskAssetResponse]
    asset_inventory_by_type: dict[str, int]
    total_assets: int
    zone_counts: dict[str, int]
    validation_run_counts: dict[str, int]

    @classmethod
    def from_dto(cls, dto: CommandOverviewDTO) -> CommandOverviewResponse:
        return cls(
            posture_score=dto.posture_score,
            posture_band=dto.posture_band,
            posture_formula_version=dto.posture_formula_version,
            posture_total_deduction=dto.posture_total_deduction,
            posture_contributions=[
                PostureContributionResponse(**asdict(c)) for c in dto.posture_contributions
            ],
            active_condition_count=dto.active_condition_count,
            active_conditions_by_severity=dto.active_conditions_by_severity,
            active_correlation_count=dto.active_correlation_count,
            high_risk_assets=[HighRiskAssetResponse(**asdict(a)) for a in dto.high_risk_assets],
            asset_inventory_by_type=dto.asset_inventory_by_type,
            total_assets=dto.total_assets,
            zone_counts=dto.zone_counts,
            validation_run_counts=dto.validation_run_counts,
        )


class BehaviorEvidenceResponse(BaseModel):
    source: str
    source_id: str
    occurred_at: str
    detail: str


class BehaviorSignalResponse(BaseModel):
    domain: str
    signal_type: str
    severity: str
    subject: str
    summary: str
    observed_window: str
    evidence_count: int
    evidence: list[BehaviorEvidenceResponse]


class IntegrationStatusResponse(BaseModel):
    integration_type: str
    provider_name: str | None
    status: str
    last_telemetry_at: str | None
    detail: str


class RegisterProviderRequest(BaseModel):
    provider_name: str = Field(min_length=1, max_length=100)
    config: dict[str, str] | None = None


class ZoneAssignmentResponse(BaseModel):
    asset_id: str
    asset_name: str
    asset_type: str
    zone_type: str
    note: str
    assigned_by: str
    updated_at: str


class DmzAssetResponse(BaseModel):
    asset_id: str
    asset_name: str
    asset_type: str
    active_condition_count: int


class ZoneOverviewResponse(BaseModel):
    counts_by_zone: dict[str, int]
    dmz_assets: list[DmzAssetResponse]


class AssignZoneRequest(BaseModel):
    asset_id: str = Field(min_length=1, max_length=26)
    zone_type: str = Field(min_length=1, max_length=20)
    note: str = Field(default="", max_length=500)


# ─── Overview ──────────────────────────────────────────────────────────────


@router.get("/overview", response_model=CommandOverviewResponse)
async def get_overview(
    tenant: TenantContext = Depends(require_permission(Permission.SECURITY_OPERATIONS_READ)),
    service: CommandOverviewService = Depends(get_command_overview_service),
) -> CommandOverviewResponse:
    dto = await service.get_overview(tenant.organization_id)
    return CommandOverviewResponse.from_dto(dto)


# ─── Behavior analytics (UEBA/HBA/NBA) ─────────────────────────────────────


@router.get("/behavior", response_model=list[BehaviorSignalResponse])
async def list_behavior_signals(
    period: BoundedPeriod = Query(default=BoundedPeriod.TWENTY_FOUR_HOURS),
    domain: BehaviorDomain | None = Query(default=None),
    tenant: TenantContext = Depends(require_permission(Permission.SECURITY_OPERATIONS_READ)),
    service: BehaviorAnalyticsService = Depends(get_behavior_analytics_service),
) -> list[BehaviorSignalResponse]:
    """Deterministic behavior signals over real audit / drift rows. Each
    carries the exact source rows that produced it (`evidence`)."""
    signals = await service.signals(tenant.organization_id, period, domain)
    return [
        BehaviorSignalResponse(
            domain=s.domain, signal_type=s.signal_type, severity=s.severity, subject=s.subject,
            summary=s.summary, observed_window=s.observed_window,
            evidence_count=s.evidence_count,
            evidence=[BehaviorEvidenceResponse(**asdict(e)) for e in s.evidence],
        )
        for s in signals
    ]


# ─── Integration boundaries (NOT CONFIGURED until wired) ───────────────────


@router.get("/integrations", response_model=list[IntegrationStatusResponse])
async def list_integrations(
    tenant: TenantContext = Depends(require_permission(Permission.SECURITY_OPERATIONS_READ)),
    service: IntegrationStatusService = Depends(get_integration_status_service),
) -> list[IntegrationStatusResponse]:
    """Status of all six external-telemetry integrations. Each is
    NOT_CONFIGURED unless a provider descriptor has been registered; the
    platform never fabricates telemetry values."""
    rows = await service.list_status(tenant.organization_id)
    return [IntegrationStatusResponse(**asdict(r)) for r in rows]


@router.put("/integrations/{integration_type}", response_model=IntegrationStatusResponse)
async def register_integration(
    integration_type: str,
    body: RegisterProviderRequest,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: IntegrationStatusService = Depends(get_integration_status_service),
) -> IntegrationStatusResponse:
    """Register/replace a provider DESCRIPTOR for an integration type.
    Config is allowlisted to non-secret reference fields; a registered
    provider with no telemetry reports AWAITING_TELEMETRY — never a
    fabricated ACTIVE. An unknown integration type is a 422."""
    dto = await service.register_provider(
        organization_id=tenant.organization_id, actor_id=tenant.user_id,
        integration_type=integration_type, provider_name=body.provider_name, config=body.config,
    )
    return IntegrationStatusResponse(**asdict(dto))


@router.delete("/integrations/{integration_type}")
async def disable_integration(
    integration_type: str,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: IntegrationStatusService = Depends(get_integration_status_service),
) -> dict[str, bool]:
    removed = await service.disable_provider(
        organization_id=tenant.organization_id, actor_id=tenant.user_id,
        integration_type=integration_type,
    )
    return {"removed": removed}


# ─── Network zones / DMZ ───────────────────────────────────────────────────


@router.get("/zones/overview", response_model=ZoneOverviewResponse)
async def zone_overview(
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_READ)),
    service: NetworkZoneService = Depends(get_network_zone_service),
) -> ZoneOverviewResponse:
    dto = await service.overview(tenant.organization_id)
    return ZoneOverviewResponse(
        counts_by_zone=dto.counts_by_zone,
        dmz_assets=[DmzAssetResponse(**asdict(a)) for a in dto.dmz_assets],
    )


@router.get("/zones", response_model=list[ZoneAssignmentResponse])
async def list_zone_assignments(
    zone_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_READ)),
    service: NetworkZoneService = Depends(get_network_zone_service),
) -> list[ZoneAssignmentResponse]:
    rows = await service.list_assignments(tenant.organization_id, zone_type, limit, offset)
    return [ZoneAssignmentResponse(**asdict(r)) for r in rows]


@router.post("/zones", response_model=ZoneAssignmentResponse, status_code=201)
async def assign_zone(
    body: AssignZoneRequest,
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_MANAGE)),
    service: NetworkZoneService = Depends(get_network_zone_service),
) -> ZoneAssignmentResponse:
    """Explicitly classify an asset into a network zone. Unknown zone
    type → 422; asset not in this org → 404. Never an IP-heuristic guess."""
    dto = await service.assign(
        organization_id=tenant.organization_id, actor_id=tenant.user_id,
        asset_id=body.asset_id, zone_type=body.zone_type, note=body.note,
    )
    return ZoneAssignmentResponse(**asdict(dto))


@router.delete("/zones/{asset_id}")
async def unassign_zone(
    asset_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_MANAGE)),
    service: NetworkZoneService = Depends(get_network_zone_service),
) -> dict[str, bool]:
    removed = await service.unassign(
        organization_id=tenant.organization_id, actor_id=tenant.user_id, asset_id=asset_id,
    )
    return {"removed": removed}
