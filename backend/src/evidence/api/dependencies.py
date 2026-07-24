"""FastAPI dependencies for evidence routes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, Request

from evidence.application.services.evidence_application_service import (
    EvidenceApplicationService,
)
from redforge.api.security import TenantContext, get_tenant_context
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from evidence.infrastructure.container import EvidenceContainer


async def get_evidence_container(request: Request) -> EvidenceContainer:
    container: EvidenceContainer = request.app.state.evidence_container
    return container


def get_tenant_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> EntityId:
    return EntityId.from_string(tenant.organization_id)


def get_principal_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> EntityId:
    return EntityId.from_string(tenant.user_id)


async def get_evidence_service(
    container: EvidenceContainer = Depends(get_evidence_container),
) -> EvidenceApplicationService:
    return container.evidence_service


EvidenceServiceDep = Annotated[
    EvidenceApplicationService, Depends(get_evidence_service)
]
TenantIdDep = Annotated[EntityId, Depends(get_tenant_uuid)]
PrincipalIdDep = Annotated[EntityId, Depends(get_principal_uuid)]
