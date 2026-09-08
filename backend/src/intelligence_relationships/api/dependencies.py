"""FastAPI dependencies for intelligence_relationships routes (M51.4
Phase C1). Follows `attack_pattern_intel.api.dependencies`'s shape
exactly: a container pulled off `request.app.state`, tenant identity
resolved only from the signed access token via `redforge.api.security`
— `tenant_id` is NEVER accepted from a request body field, only
derived here."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from intelligence_relationships.application.services.relationship_application_service import (
    IntelligenceRelationshipApplicationService,
)
from redforge.api.dependencies import (
    get_effective_access_service,
    get_token_service,
    get_user_status_service,
)
from redforge.api.security import (
    PlatformContext,
    TenantContext,
    get_platform_context,
    get_tenant_context,
)
from redforge.core.exceptions import AuthorizationError
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from intelligence_relationships.infrastructure.container import (
        IntelligenceRelationshipsContainer,
    )
    from redforge.application.auth import UserStatusService
    from redforge.application.rbac import EffectiveAccessService
    from redforge.infrastructure.auth.contracts import TokenService

# A second, independent HTTPBearer extractor — not a shared singleton
# with `redforge.api.security`'s private `_bearer_scheme`, mirroring
# `attack_pattern_intel.api.dependencies`'s identical precedent.
_bearer_scheme = HTTPBearer(auto_error=False)


async def get_intelligence_relationships_container(
    request: Request,
) -> IntelligenceRelationshipsContainer:
    container: IntelligenceRelationshipsContainer = (
        request.app.state.intelligence_relationships_container
    )
    return container


async def get_intelligence_relationships_session(
    container: IntelligenceRelationshipsContainer = Depends(
        get_intelligence_relationships_container
    ),
) -> AsyncGenerator[AsyncSession, None]:
    session = container.new_session()
    try:
        yield session
    finally:
        await session.close()


def get_tenant_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> EntityId:
    return EntityId.from_string(tenant.organization_id)


async def get_optional_tenant_context(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    token_service: TokenService = Depends(get_token_service),
    user_status_service: UserStatusService = Depends(get_user_status_service),
    effective_access_service: EffectiveAccessService = Depends(get_effective_access_service),
) -> TenantContext | None:
    try:
        return await get_tenant_context(
            credentials=credentials,
            token_service=token_service,
            user_status_service=user_status_service,
            effective_access_service=effective_access_service,
        )
    except AuthorizationError:
        return None


async def get_relationship_service(
    container: IntelligenceRelationshipsContainer = Depends(
        get_intelligence_relationships_container
    ),
    session: AsyncSession = Depends(get_intelligence_relationships_session),
) -> IntelligenceRelationshipApplicationService:
    return container.build_service(session)


TenantIdDep = Annotated[EntityId, Depends(get_tenant_uuid)]
RelationshipServiceDep = Annotated[
    IntelligenceRelationshipApplicationService, Depends(get_relationship_service)
]
OptionalTenantContextDep = Annotated[TenantContext | None, Depends(get_optional_tenant_context)]
PlatformContextDep = Annotated[PlatformContext, Depends(get_platform_context)]
