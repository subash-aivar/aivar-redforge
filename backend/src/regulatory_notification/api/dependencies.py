from __future__ import annotations

from uuid import UUID

from fastapi import Header, Request

from regulatory_notification.infrastructure.container import RegulatoryNotificationContainer


def get_container(request: Request) -> RegulatoryNotificationContainer:
    c = getattr(request.app.state, "regulatory_container", None)
    if c is None:
        c = RegulatoryNotificationContainer()
        request.app.state.regulatory_container = c
    return c


def tenant_id_header(x_tenant_id: str = Header(..., alias="X-Tenant-Id")) -> UUID:
    return UUID(x_tenant_id)


def roles_header(
    x_regulatory_roles: str = Header("regulatory:officer", alias="X-Regulatory-Roles"),
) -> tuple[str, ...]:
    return tuple(r.strip() for r in x_regulatory_roles.split(",") if r.strip())
