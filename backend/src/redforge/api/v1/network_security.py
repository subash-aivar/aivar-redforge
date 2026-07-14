"""Advanced Network Security & Continuous Network Monitoring REST API — M16.

Every route is tenant-scoped via TenantContext. organization_id is
NEVER accepted from the client. No endpoint accepts a command, script,
module, exploit, payload, or raw scanner-flag field — the only launch
input is a target AIAsset id and a closed NetworkValidationProfile enum
string; the server builds the entire bounded plan (see
application/network_security/planner.py). Every concrete address is
independently re-checked against M10 authorization before any probe
(see application/network_security/authorization_scope.py) — this
API's NETWORK_SECURITY_MANAGE permission never bypasses that gate.

Route ordering matters: literal-path routes are registered before
`/{asset_id}`/`/{policy_id}` parametrized routes.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import TYPE_CHECKING, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from redforge.api.dependencies import (
    get_network_drift_query_service,
    get_network_exposure_service,
    get_network_inventory_service,
    get_network_monitoring_policy_service,
    get_network_monitoring_processor,
    get_network_validation_run_query_service,
)
from redforge.api.security import TenantContext, require_permission
from redforge.application.command_center.drift_query_service import (
    NetworkDriftQueryService,  # noqa: TC001
)
from redforge.application.command_center.exposure_service import (
    NetworkExposureService,  # noqa: TC001
)
from redforge.application.network_security.inventory_service import (
    NetworkInventoryService,  # noqa: TC001
)
from redforge.application.network_security.policy_service import (
    NetworkMonitoringPolicyService,  # noqa: TC001
)
from redforge.application.network_security.run_query_service import (
    NetworkValidationRunQueryService,  # noqa: TC001
)
from redforge.application.network_security.scheduler import (
    NetworkMonitoringProcessor,  # noqa: TC001
)
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.network_security.inventory_service import (
        NetworkAssetDetailDTO,
        NetworkInventoryEntryDTO,
    )
    from redforge.application.network_security.orchestrator import NetworkValidationRunDTO
    from redforge.application.network_security.policy_service import (
        NetworkMonitoringPolicyDTO,
    )
    from redforge.application.network_security.run_query_service import (
        NetworkValidationRunDetailDTO,
    )

router = APIRouter(prefix="/network-security", tags=["network-security"])


# ─── Request/Response models ───────────────────────────────────────────────


class CreatePolicyRequest(BaseModel):
    """organization_id and requester_user_id are intentionally NOT
    fields — derived from the caller's verified TenantContext. There is
    no field for ports/scanner flags/commands — target_asset_id must
    already be a canonical NETWORK or IP_ADDRESS AIAsset. `profile` and
    `cadence` are typed as `Literal` (not bare `str`) so an unsupported
    value is rejected by Pydantic itself with a controlled 422 before
    the request ever reaches the service layer — never an unhandled
    500 from a raw `Enum(value)` call downstream."""

    target_asset_id: str
    profile: Literal["network_baseline", "network_standard", "network_deep_safe"] = Field(
        default="network_baseline",
    )
    cadence: Literal["hourly", "every_6_hours", "daily", "weekly"] = Field(default="daily")


class PolicyResponse(BaseModel):
    id: str
    organization_id: str
    target_asset_id: str
    requester_user_id: str
    profile: str
    cadence: str
    lifecycle: str
    next_due_at: str | None
    last_scheduled_at: str | None

    @classmethod
    def from_dto(cls, dto: NetworkMonitoringPolicyDTO) -> PolicyResponse:
        return cls(
            id=dto.id, organization_id=dto.organization_id,
            target_asset_id=dto.target_asset_id, requester_user_id=dto.requester_user_id,
            profile=dto.profile, cadence=dto.cadence, lifecycle=dto.lifecycle,
            next_due_at=dto.next_due_at, last_scheduled_at=dto.last_scheduled_at,
        )


class RunNowResponse(BaseModel):
    run_id: str
    status: str
    authorization_id: str | None
    reachable_ports: list[int]
    denied_addresses: list[str]

    @classmethod
    def from_dto(cls, dto: NetworkValidationRunDTO) -> RunNowResponse:
        return cls(
            run_id=dto.id, status=dto.status, authorization_id=dto.authorization_id,
            reachable_ports=dto.reachable_ports, denied_addresses=dto.denied_addresses,
        )


class InventoryEntryResponse(BaseModel):
    asset_id: str
    address: str
    address_classification: str
    observed_services: list[str]
    active_condition_count: int
    last_observed_at: str
    monitoring_status: str

    @classmethod
    def from_dto(cls, dto: NetworkInventoryEntryDTO) -> InventoryEntryResponse:
        return cls(
            asset_id=dto.asset_id, address=dto.address,
            address_classification=dto.address_classification,
            observed_services=dto.observed_services,
            active_condition_count=dto.active_condition_count,
            last_observed_at=dto.last_observed_at, monitoring_status=dto.monitoring_status,
        )


class AssetDetailResponse(BaseModel):
    asset_id: str
    address: str
    address_classification: str
    first_observed_at: str
    last_observed_at: str
    services: list[dict[str, str]]
    active_conditions: list[dict[str, str]]
    active_correlations: list[dict[str, str]]
    monitoring_policy_id: str | None
    monitoring_lifecycle: str | None

    @classmethod
    def from_dto(cls, dto: NetworkAssetDetailDTO) -> AssetDetailResponse:
        return cls(
            asset_id=dto.asset_id, address=dto.address,
            address_classification=dto.address_classification,
            first_observed_at=dto.first_observed_at, last_observed_at=dto.last_observed_at,
            services=dto.services, active_conditions=dto.active_conditions,
            active_correlations=dto.active_correlations,
            monitoring_policy_id=dto.monitoring_policy_id,
            monitoring_lifecycle=dto.monitoring_lifecycle,
        )


# ─── Inventory endpoints ────────────────────────────────────────────────────


@router.get("/inventory", response_model=list[InventoryEntryResponse])
async def get_inventory(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_READ)),
    service: NetworkInventoryService = Depends(get_network_inventory_service),
) -> list[InventoryEntryResponse]:
    entries = await service.list_inventory(tenant.organization_id, limit, offset)
    return [InventoryEntryResponse.from_dto(e) for e in entries]


@router.get("/assets/{asset_id}", response_model=AssetDetailResponse)
async def get_asset_detail(
    asset_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_READ)),
    service: NetworkInventoryService = Depends(get_network_inventory_service),
) -> AssetDetailResponse:
    dto = await service.get_asset_detail(tenant.organization_id, asset_id)
    return AssetDetailResponse.from_dto(dto)


# ─── Monitoring policy endpoints ────────────────────────────────────────────


@router.post("/monitoring-policies", response_model=PolicyResponse, status_code=201)
async def create_policy(
    body: CreatePolicyRequest,
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_MANAGE)),
    service: NetworkMonitoringPolicyService = Depends(get_network_monitoring_policy_service),
) -> PolicyResponse:
    from redforge.domain.network_security.value_objects import (
        NetworkValidationProfile,
        ValidationCadence,
    )

    dto = await service.create(
        organization_id=tenant.organization_id, target_asset_id=body.target_asset_id,
        requester_user_id=tenant.user_id, profile=NetworkValidationProfile(body.profile),
        cadence=ValidationCadence(body.cadence),
    )
    return PolicyResponse.from_dto(dto)


@router.get("/monitoring-policies", response_model=list[PolicyResponse])
async def list_policies(
    lifecycle: Literal["draft", "active", "paused", "disabled"] | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_READ)),
    service: NetworkMonitoringPolicyService = Depends(get_network_monitoring_policy_service),
) -> list[PolicyResponse]:
    dtos = await service.list_for_org(tenant.organization_id, lifecycle, limit, offset)
    return [PolicyResponse.from_dto(d) for d in dtos]


@router.get("/monitoring-policies/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_READ)),
    service: NetworkMonitoringPolicyService = Depends(get_network_monitoring_policy_service),
) -> PolicyResponse:
    dto = await service.get_for_org(policy_id, tenant.organization_id)
    return PolicyResponse.from_dto(dto)


@router.post("/monitoring-policies/{policy_id}/activate", response_model=PolicyResponse)
async def activate_policy(
    policy_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_MANAGE)),
    service: NetworkMonitoringPolicyService = Depends(get_network_monitoring_policy_service),
) -> PolicyResponse:
    dto = await service.activate(policy_id, tenant.organization_id)
    return PolicyResponse.from_dto(dto)


@router.post("/monitoring-policies/{policy_id}/pause", response_model=PolicyResponse)
async def pause_policy(
    policy_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_MANAGE)),
    service: NetworkMonitoringPolicyService = Depends(get_network_monitoring_policy_service),
) -> PolicyResponse:
    dto = await service.pause(policy_id, tenant.organization_id)
    return PolicyResponse.from_dto(dto)


@router.post("/monitoring-policies/{policy_id}/resume", response_model=PolicyResponse)
async def resume_policy(
    policy_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_MANAGE)),
    service: NetworkMonitoringPolicyService = Depends(get_network_monitoring_policy_service),
) -> PolicyResponse:
    dto = await service.resume(policy_id, tenant.organization_id)
    return PolicyResponse.from_dto(dto)


@router.post("/monitoring-policies/{policy_id}/disable", response_model=PolicyResponse)
async def disable_policy(
    policy_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_MANAGE)),
    service: NetworkMonitoringPolicyService = Depends(get_network_monitoring_policy_service),
) -> PolicyResponse:
    dto = await service.disable(policy_id, tenant.organization_id)
    return PolicyResponse.from_dto(dto)


@router.post("/monitoring-policies/{policy_id}/run-now", response_model=RunNowResponse)
async def run_now(
    policy_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_MANAGE)),
    processor: NetworkMonitoringProcessor = Depends(get_network_monitoring_processor),
) -> RunNowResponse:
    """Operator-triggered authorized network validation against an
    existing monitoring policy's target. Fresh M10 authorization is
    re-checked per address inside the orchestrator — this endpoint
    never bypasses it."""
    dto = await processor.run_now(tenant.organization_id, policy_id)
    return RunNowResponse.from_dto(dto)


# ─── Network validation run endpoints ───────────────────────────────────────


class RunDetailResponse(BaseModel):
    id: str
    organization_id: str
    target_asset_id: str
    requester_user_id: str
    profile: str
    status: str
    trigger: str
    continuous_policy_id: str | None
    authorization_id: str | None
    created_at: str
    started_at: str | None
    finished_at: str | None
    cancellation_requested: bool

    @classmethod
    def from_dto(cls, dto: NetworkValidationRunDetailDTO) -> RunDetailResponse:
        return cls(
            id=dto.id, organization_id=dto.organization_id,
            target_asset_id=dto.target_asset_id, requester_user_id=dto.requester_user_id,
            profile=dto.profile, status=dto.status, trigger=dto.trigger,
            continuous_policy_id=dto.continuous_policy_id,
            authorization_id=dto.authorization_id, created_at=dto.created_at,
            started_at=dto.started_at, finished_at=dto.finished_at,
            cancellation_requested=dto.cancellation_requested,
        )


@router.get("/runs", response_model=list[RunDetailResponse])
async def list_runs(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_READ)),
    service: NetworkValidationRunQueryService = Depends(
        get_network_validation_run_query_service,
    ),
) -> list[RunDetailResponse]:
    dtos = await service.list_for_org(tenant.organization_id, limit, offset)
    return [RunDetailResponse.from_dto(d) for d in dtos]


@router.get("/runs/{run_id}", response_model=RunDetailResponse)
async def get_run(
    run_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_READ)),
    service: NetworkValidationRunQueryService = Depends(
        get_network_validation_run_query_service,
    ),
) -> RunDetailResponse:
    dto = await service.get_for_org(run_id, tenant.organization_id)
    return RunDetailResponse.from_dto(dto)


@router.post("/runs/{run_id}/cancel", response_model=RunDetailResponse)
async def cancel_run(
    run_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_MANAGE)),
    service: NetworkValidationRunQueryService = Depends(
        get_network_validation_run_query_service,
    ),
) -> RunDetailResponse:
    """Idempotent: cancelling an already-terminal run (COMPLETED,
    PARTIALLY_COMPLETED, FAILED, or already-CANCELLED) is a no-op that
    simply returns its current, unchanged detail rather than an error —
    there is no meaningful distinction between "already cancelled" and
    "cancel it again" from the caller's perspective. A malformed run_id
    or a run belonging to another tenant both resolve to the same 404
    (see run_query_service.request_cancellation), so cross-tenant probing
    cannot distinguish "doesn't exist" from "exists but isn't yours"."""
    dto = await service.request_cancellation(run_id, tenant.organization_id)
    return RunDetailResponse.from_dto(dto)


# ─── Exposure & drift read surfaces (M18) ──────────────────────────────────
# All strictly tenant-scoped reads over real M16 observations/drift; no
# new authoritative truth. Every route is gated by NETWORK_SECURITY_READ.


class NetworkDriftEventResponse(BaseModel):
    id: str
    category: str
    summary: str
    policy_id: str
    run_id: str
    detected_at: str
    severity: str = "notice"
    target_asset_id: str = ""
    target_asset_name: str = ""


class PortExposureResponse(BaseModel):
    port: int
    transport: str
    asset_count: int
    observation_count: int
    last_observed_at: str


class PortAssetResponse(BaseModel):
    asset_id: str
    observation_count: int
    last_observed_at: str
    asset_name: str = ""


class ServiceExposureResponse(BaseModel):
    service: str
    validator_id: str
    asset_count: int
    observation_count: int
    last_observed_at: str


@router.get("/drift", response_model=list[NetworkDriftEventResponse])
async def list_network_drift(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_READ)),
    service: NetworkDriftQueryService = Depends(get_network_drift_query_service),
) -> list[NetworkDriftEventResponse]:
    """Org-scoped network drift feed — the read surface for the M16
    `network_drift_events` table (which is also now surfaced in the M15
    live operations feed)."""
    events = await service.list_for_org(tenant.organization_id, limit, offset)
    return [NetworkDriftEventResponse(**asdict(e)) for e in events]


@router.get("/top-ports", response_model=list[PortExposureResponse])
async def list_top_open_ports(
    limit: int = Query(default=25, ge=1, le=200),
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_READ)),
    service: NetworkExposureService = Depends(get_network_exposure_service),
) -> list[PortExposureResponse]:
    """Real aggregate over `tcp_reachability` observations that were
    actually reachable. A port only appears if it was genuinely observed
    open; transport is TCP because that is what was observed, not a guess."""
    rows = await service.top_open_ports(tenant.organization_id, limit)
    return [PortExposureResponse(**asdict(r)) for r in rows]


@router.get("/top-ports/{port}/assets", response_model=list[PortAssetResponse])
async def list_assets_for_port(
    port: int,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_READ)),
    service: NetworkExposureService = Depends(get_network_exposure_service),
) -> list[PortAssetResponse]:
    """Drill-down: which assets have this port observed reachable."""
    rows = await service.assets_for_port(tenant.organization_id, port, limit, offset)
    return [PortAssetResponse(**asdict(r)) for r in rows]


@router.get("/service-exposure", response_model=list[ServiceExposureResponse])
async def list_service_exposure(
    limit: int = Query(default=50, ge=1, le=200),
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_READ)),
    service: NetworkExposureService = Depends(get_network_exposure_service),
) -> list[ServiceExposureResponse]:
    """Validated services observed across the org — grouped by the
    protocol a validator actually confirmed, never guessed from a port
    number or banner."""
    rows = await service.validated_services(tenant.organization_id, limit)
    return [ServiceExposureResponse(**asdict(r)) for r in rows]
