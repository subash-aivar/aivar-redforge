from __future__ import annotations

from uuid import UUID

from fastapi import Header, Request

from lessons_learned.infrastructure.container import LessonsLearnedContainer


def get_container(request: Request) -> LessonsLearnedContainer:
    c = getattr(request.app.state, "lessons_container", None)
    if c is None:
        c = LessonsLearnedContainer()
        request.app.state.lessons_container = c
    return c


def tenant_id_header(x_tenant_id: str = Header(..., alias="X-Tenant-Id")) -> UUID:
    return UUID(x_tenant_id)


def roles_header(
    x_lessons_roles: str = Header("lessons_learned:contributor", alias="X-Lessons-Roles"),
) -> tuple[str, ...]:
    return tuple(r.strip() for r in x_lessons_roles.split(",") if r.strip())
