"""FastAPI dependencies for payload routes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, Request

from payload.application.services.payload_application_service import (
    PayloadApplicationService,
)
from redforge.api.security import TenantContext, get_tenant_context
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from payload.infrastructure.container import PayloadContainer


async def get_payload_container(request: Request) -> PayloadContainer:
    container: PayloadContainer = request.app.state.payload_container
    return container


def get_tenant_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> EntityId:
    return EntityId.from_string(tenant.organization_id)


def get_principal_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> EntityId:
    return EntityId.from_string(tenant.user_id)


async def get_payload_service(
    container: PayloadContainer = Depends(get_payload_container),
) -> PayloadApplicationService:
    return container.payload_service


PayloadServiceDep = Annotated[
    PayloadApplicationService, Depends(get_payload_service)
]
TenantIdDep = Annotated[EntityId, Depends(get_tenant_uuid)]
PrincipalIdDep = Annotated[EntityId, Depends(get_principal_uuid)]
