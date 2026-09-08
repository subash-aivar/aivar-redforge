"""FastAPI dependencies for threat_actor_intel routes (M51.1 Phase 4).
Follows `risk_engine.api.dependencies`'s shape exactly: a container
pulled off `request.app.state`, tenant identity resolved only from the
signed access token via `redforge.api.security` — `tenant_id` is
NEVER accepted from a request body field, only derived here."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, Request

from redforge.api.security import TenantContext, get_tenant_context
from redforge.shared.identifiers import EntityId
from threat_actor_intel.application.services.threat_actor_application_service import (
    ThreatActorApplicationService,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from threat_actor_intel.infrastructure.container import ThreatActorIntelContainer


async def get_threat_actor_intel_container(request: Request) -> ThreatActorIntelContainer:
    container: ThreatActorIntelContainer = request.app.state.threat_actor_intel_container
    return container


async def get_threat_actor_intel_session(
    container: ThreatActorIntelContainer = Depends(get_threat_actor_intel_container),
) -> AsyncGenerator[AsyncSession, None]:
    session = container.new_session()
    try:
        yield session
    finally:
        await session.close()


def get_tenant_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> EntityId:
    return EntityId.from_string(tenant.organization_id)


async def get_threat_actor_service(
    container: ThreatActorIntelContainer = Depends(get_threat_actor_intel_container),
    session: AsyncSession = Depends(get_threat_actor_intel_session),
) -> ThreatActorApplicationService:
    return container.build_service(session)


TenantIdDep = Annotated[EntityId, Depends(get_tenant_uuid)]
ThreatActorServiceDep = Annotated[ThreatActorApplicationService, Depends(get_threat_actor_service)]
