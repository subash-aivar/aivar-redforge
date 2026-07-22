from __future__ import annotations

from uuid import UUID

from fastapi import Depends, Header, Request

from redforge.api.security import TenantContext, get_tenant_context
from regulatory_notification.infrastructure.container import RegulatoryNotificationContainer


def get_container(request: Request) -> RegulatoryNotificationContainer:
    c = getattr(request.app.state, "regulatory_container", None)
    if c is None:
        c = RegulatoryNotificationContainer()
        request.app.state.regulatory_container = c
    return c


def tenant_id_header(tenant: TenantContext = Depends(get_tenant_context)) -> UUID:
    """Verified tenant scope from the caller's signed access token.

    Previously read the client-supplied `X-Tenant-Id` header directly —
    any caller could set that header to an arbitrary organization UUID
    and read/write that org's regulatory-notification data.
    get_tenant_context verifies the bearer token and its `org` claim
    server-side, so organization_id can no longer be spoofed via a
    request header.
    """
    return UUID(tenant.organization_id)


def roles_header(
    x_regulatory_roles: str = Header("regulatory:officer", alias="X-Regulatory-Roles"),
) -> tuple[str, ...]:
    return tuple(r.strip() for r in x_regulatory_roles.split(",") if r.strip())
