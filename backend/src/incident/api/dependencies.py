from __future__ import annotations

from uuid import UUID

from fastapi import Depends, Header, Request

from incident.infrastructure.container import IncidentContainer
from redforge.api.security import TenantContext, get_tenant_context


def get_container(request: Request) -> IncidentContainer:
    container = getattr(request.app.state, "incident_container", None)
    if container is None:
        from redforge.api.dependencies import get_session_factory

        try:
            session_factory = get_session_factory()
        except RuntimeError:
            # Engine not initialized (e.g. tests that build this router
            # without running the app's startup lifespan) — fall back to
            # the in-memory repositories rather than failing the request.
            session_factory = None
        container = IncidentContainer(session_factory=session_factory)
        request.app.state.incident_container = container
    return container


def tenant_id_header(tenant: TenantContext = Depends(get_tenant_context)) -> UUID:
    """Verified tenant scope from the caller's signed access token.

    Previously read the client-supplied `X-Tenant-Id` header directly —
    any caller could set that header to an arbitrary organization UUID
    and read/write that org's incident data. get_tenant_context verifies
    the bearer token and its `org` claim server-side, so organization_id
    can no longer be spoofed via a request header.
    """
    return UUID(tenant.organization_id)


def roles_header(
    x_incident_roles: str = Header("incident:viewer", alias="X-Incident-Roles"),
) -> tuple[str, ...]:
    return tuple(r.strip() for r in x_incident_roles.split(",") if r.strip())
