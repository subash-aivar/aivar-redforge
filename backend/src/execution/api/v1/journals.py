"""Execution journal API routes."""

from __future__ import annotations

from dataclasses import asdict
from uuid import UUID

from fastapi import APIRouter, Depends

from execution.api.dependencies import ExecutionServiceDep, TenantIdDep
from execution.api.schemas.execution_schemas import (
    ChainIntegrityResponse,
    JournalEntryResponse,
    JournalResponse,
)
from execution.application.queries.execution_queries import GetJournal, QueryJournalIntegrity
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

journals_router = APIRouter()


@journals_router.get("/{engagement_id}", response_model=JournalResponse)
async def get_journal(
    engagement_id: UUID,
    service: ExecutionServiceDep,
    tenant_id: TenantIdDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> JournalResponse:
    dto = await service.get_journal(
        GetJournal(tenant_id=tenant_id, engagement_id=engagement_id)
    )
    return JournalResponse(
        journal_id=dto.journal_id,
        tenant_id=dto.tenant_id,
        engagement_id=dto.engagement_id,
        entry_count=dto.entry_count,
        entries=[JournalEntryResponse.model_validate(asdict(e)) for e in dto.entries],
        version=dto.version,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
    )


@journals_router.get("/{engagement_id}/integrity", response_model=ChainIntegrityResponse)
async def query_journal_integrity(
    engagement_id: UUID,
    service: ExecutionServiceDep,
    tenant_id: TenantIdDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_AUDITOR)),
) -> ChainIntegrityResponse:
    dto = await service.query_journal_integrity(
        QueryJournalIntegrity(tenant_id=tenant_id, engagement_id=engagement_id)
    )
    return ChainIntegrityResponse.model_validate(asdict(dto))
