"""Audit logs API router."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Query

from credential_vault.api.dependencies import (
    AuditQueryServiceDep,
    PrincipalIdDep,
    TenantIdDep,
)
from credential_vault.api.schemas.audit_schemas import AuditEntryResponse, ListAuditEntriesResponse
from credential_vault.application.queries.audit_queries import ListAuditEntriesQuery

router = APIRouter()


@router.get(
    "/credentials/{credential_id}",
    response_model=ListAuditEntriesResponse,
)
async def list_audit_entries(
    credential_id: UUID,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    query_svc: AuditQueryServiceDep,
    operations: list[str] | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> ListAuditEntriesResponse:
    items = await query_svc.list_audit_entries(
        ListAuditEntriesQuery(
            tenant_id=tenant_id,
            credential_id=credential_id,
            principal_id=principal_id,
            operations=operations,
            limit=limit,
            offset=offset,
        )
    )
    return ListAuditEntriesResponse(items=[AuditEntryResponse.from_dto(item) for item in items])
