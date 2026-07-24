"""FastAPI dependencies for operator routes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, Request

from red_team_operator.application.services.operator_application_service import (
    OperatorApplicationService,
)
from red_team_operator.application.services.operator_query_service import OperatorQueryService
from redforge.api.dependencies import get_session_factory
from redforge.api.security import TenantContext, get_tenant_context
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from red_team_operator.infrastructure.container import OperatorContainer


async def get_operator_container(request: Request) -> OperatorContainer:
    container: OperatorContainer = request.app.state.operator_container
    return container


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    factory: async_sessionmaker[AsyncSession] = get_session_factory()
    async with factory() as session:
        yield session


def get_tenant_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> EntityId:
    return EntityId.from_string(tenant.organization_id)


async def get_operator_service(
    container: OperatorContainer = Depends(get_operator_container),
) -> OperatorApplicationService:
    return container.operator_service


async def get_operator_query_service(
    container: OperatorContainer = Depends(get_operator_container),
    session: AsyncSession = Depends(get_async_session),
) -> OperatorQueryService:
    return container.make_operator_query_service(session)


OperatorServiceDep = Annotated[OperatorApplicationService, Depends(get_operator_service)]
OperatorQueryServiceDep = Annotated[
    OperatorQueryService, Depends(get_operator_query_service)
]
TenantIdDep = Annotated[EntityId, Depends(get_tenant_uuid)]
