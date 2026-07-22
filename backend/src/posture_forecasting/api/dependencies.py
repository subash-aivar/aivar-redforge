from __future__ import annotations

from uuid import UUID

from fastapi import Depends, Header, Request

from posture_forecasting.infrastructure.container import PostureForecastingContainer
from redforge.api.security import TenantContext, get_tenant_context


def get_container(request: Request) -> PostureForecastingContainer:
    c = getattr(request.app.state, "posture_forecasting_container", None)
    if c is None:
        from redforge.api.dependencies import get_session_factory

        try:
            session_factory = get_session_factory()
        except RuntimeError:
            session_factory = None
        c = PostureForecastingContainer(session_factory=session_factory)
        request.app.state.posture_forecasting_container = c
    return c


def tenant_id_header(tenant: TenantContext = Depends(get_tenant_context)) -> UUID:
    """Verified tenant scope from the caller's signed access token.

    Previously read the client-supplied `X-Tenant-Id` header directly —
    any caller could set that header to an arbitrary organization UUID
    and read/write that org's posture-forecasting data. get_tenant_context
    verifies the bearer token and its `org` claim server-side, so
    organization_id can no longer be spoofed via a request header.
    """
    return UUID(tenant.organization_id)


def roles_header(x_roles: str = Header("", alias="X-Roles")) -> tuple[str, ...]:
    return tuple(r.strip() for r in x_roles.split(",") if r.strip())
