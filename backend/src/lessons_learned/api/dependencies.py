from __future__ import annotations

from uuid import UUID

from fastapi import Depends, Header, Request

from lessons_learned.infrastructure.container import LessonsLearnedContainer
from redforge.api.security import TenantContext, get_tenant_context
from redforge.shared.identifiers import EntityId


def get_container(request: Request) -> LessonsLearnedContainer:
    c = getattr(request.app.state, "lessons_container", None)
    if c is None:
        from redforge.api.dependencies import get_session_factory

        try:
            session_factory = get_session_factory()
        except RuntimeError:
            session_factory = None
        c = LessonsLearnedContainer(session_factory=session_factory)
        request.app.state.lessons_container = c
    return c


def tenant_id_header(tenant: TenantContext = Depends(get_tenant_context)) -> UUID:
    """Verified tenant scope from the caller's signed access token.

    Previously read the client-supplied `X-Tenant-Id` header directly —
    any caller could set that header to an arbitrary organization UUID
    and read/write that org's lessons-learned data. get_tenant_context
    verifies the bearer token and its `org` claim server-side, so
    organization_id can no longer be spoofed via a request header.
    """
    return EntityId.from_string(tenant.organization_id)


def roles_header(
    x_lessons_roles: str = Header("lessons_learned:contributor", alias="X-Lessons-Roles"),
) -> tuple[str, ...]:
    return tuple(r.strip() for r in x_lessons_roles.split(",") if r.strip())
