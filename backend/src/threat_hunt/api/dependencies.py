from __future__ import annotations

from fastapi import Depends, Request

from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import Permission
from redforge.shared.identifiers import EntityId
from threat_hunt.infrastructure.container import ThreatHuntContainer


def get_container(request: Request) -> ThreatHuntContainer:
    c = getattr(request.app.state, "threat_hunt_container", None)
    if c is None:
        from redforge.api.dependencies import get_session_factory

        try:
            session_factory = get_session_factory()
        except RuntimeError:
            session_factory = None
        c = ThreatHuntContainer(session_factory=session_factory)
        request.app.state.threat_hunt_container = c
    return c


def tenant_id_header(tenant: TenantContext = Depends(get_tenant_context)) -> EntityId:
    """Verified tenant scope from the caller's signed access token.

    Previously read the client-supplied `X-Tenant-Id` header directly —
    any caller could set that header to an arbitrary organization UUID
    and read/write that org's threat-hunt data. get_tenant_context
    verifies the bearer token and its `org` claim server-side, so
    organization_id can no longer be spoofed via a request header.
    """
    return EntityId.from_string(tenant.organization_id)


def trusted_roles(tenant: TenantContext = Depends(get_tenant_context)) -> tuple[str, ...]:
    """Server-derived, non-spoofable equivalent of the removed client
    `X-Roles` header.

    SECURITY HOTFIX: the previous implementation read `X-Roles` directly
    from the request and passed those caller-supplied strings straight
    into `HuntApplicationService`'s/`ThreatHuntCandidate`'s role checks —
    any request could set `X-Roles: soc:detection_engineer` and be
    treated as an authorized reviewer regardless of who the caller
    actually was. This function is the only source of `roles` reaching
    threat_hunt's application/domain layers now: it maps the caller's
    verified `TenantContext.permissions` (checked server-side against the
    signed access token via `get_tenant_context`/`require_permission`,
    never a request header or body field) onto threat_hunt's existing
    internal role-string vocabulary, so downstream code's shape is
    unchanged while its trust source is not spoofable.

    `THREAT_HUNT_MANAGE` -> "soc:detection_engineer" (generate/promote/
    reject — matches the exact token `ThreatHuntCandidate.promote`/
    `.reject` already check for). `THREAT_HUNT_READ` -> "threat_hunt:
    read_access" (list/queue). The legacy "ai:operator"/"system" tokens
    are intentionally never synthesized here — they remain reserved for
    genuine internal/service callers that invoke `HuntApplicationService`
    in-process, never reachable through this spoofable-by-design HTTP
    header path.
    """
    roles: list[str] = []
    if tenant.has_permission(Permission.THREAT_HUNT_MANAGE):
        roles.append("soc:detection_engineer")
    if tenant.has_permission(Permission.THREAT_HUNT_READ):
        roles.append("threat_hunt:read_access")
    return tuple(roles)
