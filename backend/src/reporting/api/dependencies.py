from __future__ import annotations

from uuid import UUID

from fastapi import Header, HTTPException

from reporting.infrastructure.container import ReportingContainer

_container: ReportingContainer | None = None


async def get_container() -> ReportingContainer:
    global _container
    if _container is None:
        from redforge.api.dependencies import get_session_factory

        try:
            session_factory = get_session_factory()
        except RuntimeError:
            session_factory = None
        _container = ReportingContainer(session_factory=session_factory)
        if session_factory is not None:
            # The in-memory path self-seeds platform templates synchronously
            # in __init__ (_seed_platform_templates); the Postgres-backed
            # template repo needs the real async path so a fresh database
            # actually has the 7 platform templates report generation
            # depends on.
            await _container.ensure_templates()
    return _container


def reset_container() -> None:
    global _container
    _container = None


async def get_tenant_id(x_tenant_id: str = Header(..., alias="X-Tenant-Id")) -> UUID:
    try:
        return UUID(x_tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid X-Tenant-Id") from exc


async def get_actor_roles(
    x_analytics_roles: str = Header("analytics:viewer", alias="X-Analytics-Roles"),
) -> tuple[str, ...]:
    roles = tuple(r.strip() for r in x_analytics_roles.split(",") if r.strip())
    return roles or ("analytics:viewer",)
