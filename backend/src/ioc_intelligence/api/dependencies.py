"""FastAPI dependencies for ioc_intelligence routes (M51.2 Phase A4,
corrected in Phase A4.1). Follows `threat_actor_intel.api.dependencies`'s
shape exactly: a container pulled off `request.app.state`, tenant
identity resolved only from the signed access token via
`redforge.api.security` — `tenant_id` is NEVER accepted from a
request body field, only derived here.

Phase A4.1 adds `get_optional_tenant_context`/`OptionalTenantContextDep`
and `PlatformContextDep` — used only by canonical `/iocs/{ioc_id}/...`
routes that must derive authorization from the *loaded IOC's* ownership
scope (global vs. a specific tenant) rather than from a static route
path. `get_optional_tenant_context` reuses `redforge.api.security.
get_tenant_context` verbatim (same bearer-token decode, same live
user/membership checks) and only converts its "no organization
selected" `AuthorizationError` into `None` — a caller with no org
context at all is a legitimate case for a route that might turn out to
target a *global* IOC. A genuinely invalid/missing/expired token still
raises `AuthenticationError` (401) exactly as before; that failure
mode is never swallowed."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ioc_intelligence.application.services.ioc_application_service import IOCApplicationService
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

    from ioc_intelligence.infrastructure.container import IocIntelContainer
    from redforge.application.auth import UserStatusService
    from redforge.application.rbac import EffectiveAccessService
    from redforge.infrastructure.auth.contracts import TokenService

# A second, independent HTTPBearer extractor — not a shared singleton
# with `redforge.api.security`'s private `_bearer_scheme`. Extracting a
# bearer token from a request header is stateless and side-effect-free,
# so a second instance behaves identically; this avoids importing a
# module-private symbol from another bounded context's security module.
_bearer_scheme = HTTPBearer(auto_error=False)


async def get_ioc_intel_container(request: Request) -> IocIntelContainer:
    container: IocIntelContainer = request.app.state.ioc_intel_container
    return container


async def get_ioc_intel_session(
    container: IocIntelContainer = Depends(get_ioc_intel_container),
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
        # No organization selected, or membership no longer active —
        # not an authentication failure (that still raises and
        # propagates as 401 unchanged). This caller may still be a
        # legitimate platform principal targeting a global IOC, which
        # the route-level ownership-scope check decides next.
        return None


async def get_ioc_service(
    container: IocIntelContainer = Depends(get_ioc_intel_container),
    session: AsyncSession = Depends(get_ioc_intel_session),
) -> IOCApplicationService:
    return container.build_service(session)


TenantIdDep = Annotated[EntityId, Depends(get_tenant_uuid)]
IocServiceDep = Annotated[IOCApplicationService, Depends(get_ioc_service)]
OptionalTenantContextDep = Annotated[TenantContext | None, Depends(get_optional_tenant_context)]
PlatformContextDep = Annotated[PlatformContext, Depends(get_platform_context)]
