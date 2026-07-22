from __future__ import annotations

from uuid import UUID

from fastapi import Header, Request

from automated_action.infrastructure.container import AutomatedActionContainer


def get_container(request: Request) -> AutomatedActionContainer:
    c = getattr(request.app.state, "automated_action_container", None)
    if c is None:
        c = AutomatedActionContainer()
        request.app.state.automated_action_container = c
    return c


def tenant_id_header(x_tenant_id: UUID = Header(..., alias="X-Tenant-Id")) -> UUID:
    return x_tenant_id


def roles_header(x_roles: str = Header("", alias="X-Roles")) -> tuple[str, ...]:
    return tuple(r.strip() for r in x_roles.split(",") if r.strip())
