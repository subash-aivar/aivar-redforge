"""FastAPI dependencies for operation routes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, Request

from operation.application.services.operation_application_service import (
    OperationApplicationService,
)
from redforge.api.security import TenantContext, get_tenant_context
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from operation.infrastructure.container import OperationContainer


async def get_operation_container(request: Request) -> OperationContainer:
    container: OperationContainer = request.app.state.operation_container
    return container


def get_tenant_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> EntityId:
    return EntityId.from_string(tenant.organization_id)


def get_principal_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> EntityId:
    return EntityId.from_string(tenant.user_id)


async def get_operation_service(
    container: OperationContainer = Depends(get_operation_container),
) -> OperationApplicationService:
    return container.operation_service


OperationServiceDep = Annotated[OperationApplicationService, Depends(get_operation_service)]
TenantIdDep = Annotated[EntityId, Depends(get_tenant_uuid)]
PrincipalIdDep = Annotated[EntityId, Depends(get_principal_uuid)]
