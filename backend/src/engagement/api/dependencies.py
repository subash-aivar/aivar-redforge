"""FastAPI dependencies for engagement routes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, Request

from engagement.application.services.engagement_application_service import (
    EngagementApplicationService,
)
from redforge.api.security import TenantContext, get_tenant_context
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from engagement.infrastructure.container import EngagementContainer


async def get_engagement_container(request: Request) -> EngagementContainer:
    container: EngagementContainer = request.app.state.engagement_container
    return container


def get_tenant_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> EntityId:
    return EntityId.from_string(tenant.organization_id)


def get_principal_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> EntityId:
    return EntityId.from_string(tenant.user_id)


async def get_engagement_service(
    container: EngagementContainer = Depends(get_engagement_container),
) -> EngagementApplicationService:
    return container.engagement_service


EngagementServiceDep = Annotated[
    EngagementApplicationService, Depends(get_engagement_service)
]
TenantIdDep = Annotated[EntityId, Depends(get_tenant_uuid)]
PrincipalIdDep = Annotated[EntityId, Depends(get_principal_uuid)]
