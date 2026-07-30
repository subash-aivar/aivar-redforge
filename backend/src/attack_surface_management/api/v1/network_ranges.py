"""Network range CRUD/lifecycle API routers (M49D).

Bounded strictly by `NetworkRangeApplicationService`'s existing surface
(form_network_range, record_asset_count, activate, retire) plus
`AttackSurfaceQueryService`'s network-range reads. No new business
capability is added."""

from __future__ import annotations

from dataclasses import asdict
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from attack_surface_management.api.dependencies import (
    NetworkRangeServiceDep,
    QueryServiceDep,
    TenantIdDep,
)
from attack_surface_management.api.schemas.attack_surface_schemas import (
    FormNetworkRangeRequest,
    ListNetworkRangesResponse,
    NetworkRangeResponse,
    RecordNetworkRangeAssetCountRequest,
)
from attack_surface_management.application.commands.network_range_commands import (
    ActivateNetworkRangeCommand,
    FormNetworkRangeCommand,
    RecordNetworkRangeAssetCountCommand,
    RetireNetworkRangeCommand,
)
from attack_surface_management.application.dtos.asset_dto import NetworkRangeDTO
from attack_surface_management.application.queries.network_range_queries import (
    GetNetworkRangeQuery,
    ListNetworkRangesQuery,
)
from attack_surface_management.domain.value_objects.cidr_block import CidrBlock
from attack_surface_management.domain.value_objects.enums import (
    DiscoverySource,
    NetworkRangeLifecycleState,
)
from attack_surface_management.domain.value_objects.identifiers import NetworkRangeId
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

network_ranges_router = APIRouter()


def _network_range_response(dto: NetworkRangeDTO) -> NetworkRangeResponse:
    return NetworkRangeResponse.model_validate(asdict(dto))


@network_ranges_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=NetworkRangeResponse,
    summary="Register a discovered network range",
)
async def form_network_range(
    body: FormNetworkRangeRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: NetworkRangeServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> NetworkRangeResponse:
    try:
        cidr = CidrBlock(body.cidr)
        discovery_source = DiscoverySource(body.discovery_source) if body.discovery_source else None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    dto = await svc.form_network_range(
        FormNetworkRangeCommand(
            tenant_id=tenant_id,
            cidr=cidr,
            discovery_source=discovery_source,
            range_id=NetworkRangeId(UUID(body.range_id)) if body.range_id else None,
        )
    )
    response.headers["Location"] = (
        f"/api/v1/attack-surface-management/network-ranges/{dto.range_id}"
    )
    return _network_range_response(dto)


@network_ranges_router.get(
    "/{range_id}",
    response_model=NetworkRangeResponse,
    summary="Get a network range",
)
async def get_network_range(
    range_id: UUID,
    tenant_id: TenantIdDep,
    svc: QueryServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_READ)),
) -> NetworkRangeResponse:
    dto = await svc.get_network_range(
        GetNetworkRangeQuery(tenant_id=tenant_id, range_id=NetworkRangeId(range_id))
    )
    if dto is None:
        raise HTTPException(status_code=404, detail=f"No network range {range_id}")
    return _network_range_response(dto)


@network_ranges_router.get(
    "",
    response_model=ListNetworkRangesResponse,
    summary="List network ranges",
)
async def list_network_ranges(
    tenant_id: TenantIdDep,
    svc: QueryServiceDep,
    lifecycle_state: NetworkRangeLifecycleState | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_READ)),
) -> ListNetworkRangesResponse:
    items = await svc.list_network_ranges(
        ListNetworkRangesQuery(
            tenant_id=tenant_id,
            lifecycle_state=lifecycle_state,
            limit=limit,
            offset=offset,
        )
    )
    return ListNetworkRangesResponse(
        items=[_network_range_response(i) for i in items], count=len(items)
    )


@network_ranges_router.post(
    "/{range_id}/asset-count",
    response_model=NetworkRangeResponse,
    summary="Record the observed asset count for a network range",
)
async def record_asset_count(
    range_id: UUID,
    body: RecordNetworkRangeAssetCountRequest,
    tenant_id: TenantIdDep,
    svc: NetworkRangeServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> NetworkRangeResponse:
    dto = await svc.record_asset_count(
        RecordNetworkRangeAssetCountCommand(
            tenant_id=tenant_id, range_id=NetworkRangeId(range_id), count=body.count
        )
    )
    return _network_range_response(dto)


@network_ranges_router.post(
    "/{range_id}/activate",
    response_model=NetworkRangeResponse,
    summary="Activate a network range",
)
async def activate_network_range(
    range_id: UUID,
    tenant_id: TenantIdDep,
    svc: NetworkRangeServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> NetworkRangeResponse:
    dto = await svc.activate(
        ActivateNetworkRangeCommand(tenant_id=tenant_id, range_id=NetworkRangeId(range_id))
    )
    return _network_range_response(dto)


@network_ranges_router.post(
    "/{range_id}/retire",
    response_model=NetworkRangeResponse,
    summary="Retire a network range",
)
async def retire_network_range(
    range_id: UUID,
    tenant_id: TenantIdDep,
    svc: NetworkRangeServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> NetworkRangeResponse:
    dto = await svc.retire(
        RetireNetworkRangeCommand(tenant_id=tenant_id, range_id=NetworkRangeId(range_id))
    )
    return _network_range_response(dto)
