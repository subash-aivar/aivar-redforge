"""Cloud Security REST API — M7.

Tenant-scoped, read-only. Cloud account/resource assets themselves are
already served by the generic `/assets` API (M3) — filterable by
`asset_type` (`cloud_account`/`cloud_resource`) — this router only adds
the one M7-specific capability that doesn't fit the generic asset
surface: deterministic cloud exposure observations.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from redforge.api.dependencies import get_tenant_cloud_security_service
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.cloud_security.service import TenantCloudSecurityService

router = APIRouter(prefix="/cloud-security", tags=["cloud-security"])


class CloudSecurityObservationResponse(BaseModel):
    rule_id: str
    title: str
    summary: str
    affected_asset_id: str


@router.get("/observations", response_model=list[CloudSecurityObservationResponse])
async def list_cloud_security_observations(
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantCloudSecurityService = Depends(get_tenant_cloud_security_service),
) -> list[CloudSecurityObservationResponse]:
    """Computed on read from current canonical CLOUD_RESOURCE asset
    state — deterministic, never persisted."""
    observations = await service.list_exposure_observations(tenant.organization_id)
    return [CloudSecurityObservationResponse(**dataclasses.asdict(o)) for o in observations]
