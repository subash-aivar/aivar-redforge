from __future__ import annotations

from uuid import UUID

from fastapi import Header, Request

from autonomous_intelligence.infrastructure.container import AutonomousIntelligenceContainer


def get_container(request: Request) -> AutonomousIntelligenceContainer:
    c = getattr(request.app.state, "autonomous_intelligence_container", None)
    if c is None:
        c = AutonomousIntelligenceContainer()
        request.app.state.autonomous_intelligence_container = c
    return c


def tenant_id_header(x_tenant_id: UUID = Header(..., alias="X-Tenant-Id")) -> UUID:
    return x_tenant_id


def roles_header(x_roles: str = Header("", alias="X-Roles")) -> tuple[str, ...]:
    return tuple(r.strip() for r in x_roles.split(",") if r.strip())
