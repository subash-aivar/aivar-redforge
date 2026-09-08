"""FastAPI dependencies for attack_pattern_intel routes (M51.3 Phase
B1). Follows `ioc_intelligence.api.dependencies`'s shape exactly: a
container pulled off `request.app.state`, tenant identity resolved
only from the signed access token via `redforge.api.security` —
`tenant_id` is NEVER accepted from a request body field, only derived
here."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from attack_pattern_intel.application.services.attack_pattern_application_service import (
    AttackPatternApplicationService,
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

    from attack_pattern_intel.infrastructure.container import AttackPatternIntelContainer
    from redforge.application.auth import UserStatusService
    from redforge.application.rbac import EffectiveAccessService
    from redforge.infrastructure.auth.contracts import TokenService

# A second, independent HTTPBearer extractor — not a shared singleton
# with `redforge.api.security`'s private `_bearer_scheme`, mirroring
# `ioc_intelligence.api.dependencies`'s identical precedent.
_bearer_scheme = HTTPBearer(auto_error=False)


async def get_attack_pattern_intel_container(request: Request) -> AttackPatternIntelContainer:
    container: AttackPatternIntelContainer = request.app.state.attack_pattern_intel_container
    return container


async def get_attack_pattern_intel_session(
    container: AttackPatternIntelContainer = Depends(get_attack_pattern_intel_container),
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


async def get_attack_pattern_service(
    container: AttackPatternIntelContainer = Depends(get_attack_pattern_intel_container),
    session: AsyncSession = Depends(get_attack_pattern_intel_session),
) -> AttackPatternApplicationService:
    return container.build_service(session)


TenantIdDep = Annotated[EntityId, Depends(get_tenant_uuid)]
AttackPatternServiceDep = Annotated[
    AttackPatternApplicationService, Depends(get_attack_pattern_service)
]
OptionalTenantContextDep = Annotated[TenantContext | None, Depends(get_optional_tenant_context)]
PlatformContextDep = Annotated[PlatformContext, Depends(get_platform_context)]
