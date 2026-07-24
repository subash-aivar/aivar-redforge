from __future__ import annotations

from fastapi import Depends, Header

from ai_supply_chain.infrastructure.container import SupplyChainContainer
from redforge.api.security import TenantContext, get_tenant_context
from redforge.shared.identifiers import EntityId

_container: SupplyChainContainer | None = None


def get_container() -> SupplyChainContainer:
    global _container
    if _container is None:
        _container = SupplyChainContainer()
    return _container


def reset_container() -> None:
    global _container
    _container = None


async def get_tenant_id(tenant: TenantContext = Depends(get_tenant_context)) -> EntityId:
    """Verified tenant scope from the caller's signed access token.

    Previously read the client-supplied `X-Tenant-Id` header directly —
    any caller could set that header to an arbitrary organization UUID
    and read/write that org's AI supply-chain data. get_tenant_context
    verifies the bearer token and its `org` claim server-side, so
    organization_id can no longer be spoofed via a request header.
    """
    return EntityId.from_string(tenant.organization_id)


async def get_actor_roles(
    x_ai_posture_roles: str = Header("ai_posture:reader", alias="X-AI-Posture-Roles"),
) -> tuple[str, ...]:
    roles = tuple(r.strip() for r in x_ai_posture_roles.split(",") if r.strip())
    return roles or ("ai_posture:reader",)
