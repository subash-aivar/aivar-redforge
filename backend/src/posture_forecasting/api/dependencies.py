from __future__ import annotations

from uuid import UUID

from fastapi import Header, Request

from posture_forecasting.infrastructure.container import PostureForecastingContainer


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


def tenant_id_header(x_tenant_id: UUID = Header(..., alias="X-Tenant-Id")) -> UUID:
    return x_tenant_id


def roles_header(x_roles: str = Header("", alias="X-Roles")) -> tuple[str, ...]:
    return tuple(r.strip() for r in x_roles.split(",") if r.strip())
