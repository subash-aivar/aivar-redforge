"""FastAPI dependencies for execution routes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from fastapi import Depends, Request

from execution.application.services.execution_application_service import (
    ExecutionApplicationService,
)
from execution.application.services.projection_application_service import (
    ProjectionApplicationService,
)
from redforge.api.security import TenantContext, get_tenant_context

if TYPE_CHECKING:
    from execution.infrastructure.container import ExecutionContainer


async def get_execution_container(request: Request) -> ExecutionContainer:
    container: ExecutionContainer = request.app.state.execution_container
    return container


def get_tenant_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> UUID:
    return UUID(tenant.organization_id)


def get_principal_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> UUID:
    return UUID(tenant.user_id)


async def get_execution_service(
    container: ExecutionContainer = Depends(get_execution_container),
) -> ExecutionApplicationService:
    return container.execution_service


async def get_projection_service(
    container: ExecutionContainer = Depends(get_execution_container),
) -> ProjectionApplicationService:
    return container.projection_service


ExecutionServiceDep = Annotated[ExecutionApplicationService, Depends(get_execution_service)]
ProjectionServiceDep = Annotated[
    ProjectionApplicationService, Depends(get_projection_service)
]
TenantIdDep = Annotated[UUID, Depends(get_tenant_uuid)]
PrincipalIdDep = Annotated[UUID, Depends(get_principal_uuid)]
