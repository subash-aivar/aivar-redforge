from __future__ import annotations

from uuid import UUID

from fastapi import Header, HTTPException

from ai_supply_chain.infrastructure.container import SupplyChainContainer

_container: SupplyChainContainer | None = None


def get_container() -> SupplyChainContainer:
    global _container
    if _container is None:
        _container = SupplyChainContainer()
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
    x_ai_posture_roles: str = Header("ai_posture:reader", alias="X-AI-Posture-Roles"),
) -> tuple[str, ...]:
    roles = tuple(r.strip() for r in x_ai_posture_roles.split(",") if r.strip())
    return roles or ("ai_posture:reader",)
