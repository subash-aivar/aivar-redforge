from __future__ import annotations

from fastapi import Depends, Header

from redforge.api.security import TenantContext, get_tenant_context
from redforge.shared.identifiers import EntityId
from remediation_impact.infrastructure.container import RemediationImpactContainer

_container: RemediationImpactContainer | None = None


def get_container() -> RemediationImpactContainer:
    global _container
    if _container is None:
        from redforge.api.dependencies import get_session_factory

        try:
            session_factory = get_session_factory()
        except RuntimeError:
            session_factory = None
        _container = RemediationImpactContainer(session_factory=session_factory)
    return _container


def reset_container() -> None:
    global _container
    _container = None


async def get_tenant_id(tenant: TenantContext = Depends(get_tenant_context)) -> EntityId:
    """Verified tenant scope from the caller's signed access token.

    Previously read the client-supplied `X-Tenant-Id` header directly —
    any caller could set that header to an arbitrary organization UUID
    and read/write that org's remediation-impact data. get_tenant_context
    verifies the bearer token and its `org` claim server-side, so
    organization_id can no longer be spoofed via a request header.
    """
    return EntityId.from_string(tenant.organization_id)


async def get_actor_roles(
    x_exposure_roles: str = Header("exposure:viewer", alias="X-Exposure-Roles"),
) -> tuple[str, ...]:
    roles = tuple(r.strip() for r in x_exposure_roles.split(",") if r.strip())
    return roles or ("exposure:viewer",)
