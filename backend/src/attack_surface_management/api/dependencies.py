"""FastAPI dependencies for attack_surface_management routes.

Mirrors `risk_engine.api.dependencies` exactly: a container pulled off
`request.app.state`, tenant/principal identity resolved only from the
signed access token via `redforge.api.security`, and `Annotated`
dependency aliases for use in route signatures. Session lifecycle (open
once per request, close in a `finally`) is added here because
`AttackSurfaceManagementContainer.build_*` methods are session-scoped
(see the container's module docstring for why)."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, Request

from attack_surface_management.application.services.asset_application_service import (
    AssetApplicationService,
)
from attack_surface_management.application.services.attack_surface_query_service import (
    AttackSurfaceQueryService,
)
from attack_surface_management.application.services.network_range_application_service import (
    NetworkRangeApplicationService,
)
from redforge.api.security import TenantContext, get_tenant_context
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from attack_surface_management.infrastructure.container import (
        AttackSurfaceManagementContainer,
    )


async def get_attack_surface_management_container(
    request: Request,
) -> AttackSurfaceManagementContainer:
    container: AttackSurfaceManagementContainer = (
        request.app.state.attack_surface_management_container
    )
    return container


async def get_attack_surface_management_session(
    container: AttackSurfaceManagementContainer = Depends(get_attack_surface_management_container),
) -> AsyncGenerator[AsyncSession, None]:
    session = container.new_session()
    try:
        yield session
    finally:
        await session.close()


def get_tenant_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> EntityId:
    return EntityId.from_string(tenant.organization_id)


def get_principal_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> EntityId:
    return EntityId.from_string(tenant.user_id)


async def get_asset_service(
    container: AttackSurfaceManagementContainer = Depends(get_attack_surface_management_container),
    session: AsyncSession = Depends(get_attack_surface_management_session),
) -> AssetApplicationService:
    return container.build_asset_service(session)


async def get_network_range_service(
    container: AttackSurfaceManagementContainer = Depends(get_attack_surface_management_container),
    session: AsyncSession = Depends(get_attack_surface_management_session),
) -> NetworkRangeApplicationService:
    return container.build_network_range_service(session)


async def get_query_service(
    container: AttackSurfaceManagementContainer = Depends(get_attack_surface_management_container),
    session: AsyncSession = Depends(get_attack_surface_management_session),
) -> AttackSurfaceQueryService:
    return container.build_query_service(session)


TenantIdDep = Annotated[EntityId, Depends(get_tenant_uuid)]
PrincipalIdDep = Annotated[EntityId, Depends(get_principal_uuid)]
AssetServiceDep = Annotated[AssetApplicationService, Depends(get_asset_service)]
NetworkRangeServiceDep = Annotated[
    NetworkRangeApplicationService, Depends(get_network_range_service)
]
QueryServiceDep = Annotated[AttackSurfaceQueryService, Depends(get_query_service)]
