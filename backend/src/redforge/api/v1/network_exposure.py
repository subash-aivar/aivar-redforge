"""Network Exposure REST API — M6.

Tenant-scoped, read-only. Network/IP/host/device/service assets
themselves are already served by the generic `/assets` API (M3) —
filterable by `asset_type` (`network`/`ip_address`/`host`/`device`/
`service`) — this router only adds the one M6-specific capability that
doesn't fit the generic asset surface: deterministic network exposure
observations.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from redforge.api.dependencies import get_tenant_network_discovery_service
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.network_discovery.service import TenantNetworkDiscoveryService

router = APIRouter(prefix="/network-exposure", tags=["network-exposure"])


class NetworkSecurityObservationResponse(BaseModel):
    rule_id: str
    title: str
    summary: str
    affected_asset_id: str


@router.get("/observations", response_model=list[NetworkSecurityObservationResponse])
async def list_network_exposure_observations(
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantNetworkDiscoveryService = Depends(get_tenant_network_discovery_service),
) -> list[NetworkSecurityObservationResponse]:
    """Computed on read from current canonical NETWORK/IP_ADDRESS/
    SERVICE asset state — deterministic, never persisted."""
    observations = await service.list_exposure_observations(tenant.organization_id)
    return [NetworkSecurityObservationResponse(**dataclasses.asdict(o)) for o in observations]
