from __future__ import annotations

from fastapi import Depends, Header

from analytics.infrastructure.container import AnalyticsContainer
from redforge.api.security import TenantContext, get_tenant_context
from redforge.shared.identifiers import EntityId

_container: AnalyticsContainer | None = None


def get_container() -> AnalyticsContainer:
    global _container
    if _container is None:
        from redforge.api.dependencies import get_session_factory

        try:
            session_factory = get_session_factory()
        except RuntimeError:
            session_factory = None
        _container = AnalyticsContainer(session_factory=session_factory)
    return _container


def reset_container() -> None:
    global _container
    _container = None


async def get_tenant_id(tenant: TenantContext = Depends(get_tenant_context)) -> EntityId:
    """Verified tenant scope from the caller's signed access token.

    Previously read the client-supplied `X-Tenant-Id` header directly —
    any authenticated (or unauthenticated) caller could set that header
    to an arbitrary organization UUID and read/write that org's analytics
    data. `get_tenant_context` verifies the bearer token and its `org`
    claim server-side (see redforge/api/security.py), so organization_id
    can no longer be spoofed via a request header.
    """
    return EntityId.from_string(tenant.organization_id)


async def get_actor_roles(
    x_analytics_roles: str = Header("analytics:viewer", alias="X-Analytics-Roles"),
) -> tuple[str, ...]:
    roles = tuple(r.strip() for r in x_analytics_roles.split(",") if r.strip())
    return roles or ("analytics:viewer",)
