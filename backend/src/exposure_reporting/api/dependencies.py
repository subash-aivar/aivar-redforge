from __future__ import annotations

from uuid import UUID

from fastapi import Header, HTTPException

from exposure_reporting.infrastructure.container import ExposureReportingContainer

_container: ExposureReportingContainer | None = None


def get_container() -> ExposureReportingContainer:
    global _container
    if _container is None:
        _container = ExposureReportingContainer()
    return _container


def reset_container() -> None:
    global _container
    _container = None


async def get_tenant_id(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
) -> UUID:
    try:
        return UUID(x_tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid X-Tenant-Id") from exc


async def get_actor_roles(
    x_exposure_roles: str = Header("exposure:viewer", alias="X-Exposure-Roles"),
) -> tuple[str, ...]:
    roles = tuple(r.strip() for r in x_exposure_roles.split(",") if r.strip())
    return roles or ("exposure:viewer",)
