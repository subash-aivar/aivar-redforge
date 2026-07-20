"""FastAPI dependencies for engagement routes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from fastapi import Depends, Request

from engagement.application.services.engagement_application_service import (
    EngagementApplicationService,
)
from redforge.api.security import TenantContext, get_tenant_context

if TYPE_CHECKING:
    from engagement.infrastructure.container import EngagementContainer


async def get_engagement_container(request: Request) -> EngagementContainer:
    container: EngagementContainer = request.app.state.engagement_container
    return container


def get_tenant_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> UUID:
    return UUID(tenant.organization_id)


def get_principal_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> UUID:
    return UUID(tenant.user_id)


async def get_engagement_service(
    container: EngagementContainer = Depends(get_engagement_container),
) -> EngagementApplicationService:
    return container.engagement_service


EngagementServiceDep = Annotated[
    EngagementApplicationService, Depends(get_engagement_service)
]
TenantIdDep = Annotated[UUID, Depends(get_tenant_uuid)]
PrincipalIdDep = Annotated[UUID, Depends(get_principal_uuid)]
