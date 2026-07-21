from __future__ import annotations

from uuid import UUID

from fastapi import Header, Request

from incident.infrastructure.container import IncidentContainer


def get_container(request: Request) -> IncidentContainer:
    container = getattr(request.app.state, "incident_container", None)
    if container is None:
        container = IncidentContainer()
        request.app.state.incident_container = container
    return container


def tenant_id_header(x_tenant_id: str = Header(..., alias="X-Tenant-Id")) -> UUID:
    return UUID(x_tenant_id)


def roles_header(
    x_incident_roles: str = Header("incident:viewer", alias="X-Incident-Roles"),
) -> tuple[str, ...]:
    return tuple(r.strip() for r in x_incident_roles.split(",") if r.strip())
