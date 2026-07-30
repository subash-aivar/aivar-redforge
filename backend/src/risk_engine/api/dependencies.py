"""FastAPI dependencies for risk_engine routes.

Follows `operation.api.dependencies`' shape exactly: a container
pulled off `request.app.state`, tenant/principal identity resolved
only from the signed access token via `redforge.api.security`, and
`Annotated` dependency aliases for use in route signatures. Session
lifecycle (open once per request, close in a `finally`) is added here
because `RiskEngineContainer.build_*` methods are session-scoped
(see the container's module docstring for why).
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, Request

from redforge.api.security import TenantContext, get_tenant_context
from redforge.shared.identifiers import EntityId
from risk_engine.application.services.enterprise_risk_profile_service import (
    EnterpriseRiskProfileApplicationService,
)
from risk_engine.application.services.risk_correlation_application_service import (
    RiskCorrelationApplicationService,
)
from risk_engine.application.services.risk_query_service import RiskQueryService
from risk_engine.application.services.risk_timeline_service import RiskTimelineApplicationService

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from risk_engine.infrastructure.container import RiskEngineContainer


async def get_risk_engine_container(request: Request) -> RiskEngineContainer:
    container: RiskEngineContainer = request.app.state.risk_engine_container
    return container


async def get_risk_engine_session(
    container: RiskEngineContainer = Depends(get_risk_engine_container),
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


async def get_profile_service(
    container: RiskEngineContainer = Depends(get_risk_engine_container),
    session: AsyncSession = Depends(get_risk_engine_session),
) -> EnterpriseRiskProfileApplicationService:
    return container.build_profile_service(session)


async def get_query_service(
    container: RiskEngineContainer = Depends(get_risk_engine_container),
    session: AsyncSession = Depends(get_risk_engine_session),
) -> RiskQueryService:
    return container.build_query_service(session)


async def get_timeline_service(
    container: RiskEngineContainer = Depends(get_risk_engine_container),
    session: AsyncSession = Depends(get_risk_engine_session),
) -> RiskTimelineApplicationService:
    return container.build_timeline_service(session)


async def get_correlation_service(
    container: RiskEngineContainer = Depends(get_risk_engine_container),
    session: AsyncSession = Depends(get_risk_engine_session),
) -> RiskCorrelationApplicationService:
    return container.build_correlation_service(session)


TenantIdDep = Annotated[EntityId, Depends(get_tenant_uuid)]
PrincipalIdDep = Annotated[EntityId, Depends(get_principal_uuid)]
ProfileServiceDep = Annotated[EnterpriseRiskProfileApplicationService, Depends(get_profile_service)]
QueryServiceDep = Annotated[RiskQueryService, Depends(get_query_service)]
TimelineServiceDep = Annotated[RiskTimelineApplicationService, Depends(get_timeline_service)]
CorrelationServiceDep = Annotated[
    RiskCorrelationApplicationService, Depends(get_correlation_service)
]
