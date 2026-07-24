"""PgAuditLogRepository — append-only audit persistence."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select

from credential_vault.domain.aggregates.audit_log import AuditLog
from credential_vault.domain.entities.audit_entry import AuditEntry
from credential_vault.domain.exceptions.domain_exceptions import CredentialNotFound
from credential_vault.domain.repositories.i_audit_log_repository import IAuditLogRepository
from credential_vault.domain.value_objects.audit_types import AuditOperation, AuditOutcome
from credential_vault.domain.value_objects.identifiers import (
    AuditEntryId,
    AuditLogId,
    CredentialId,
    PrincipalId,
    TenantId,
    VersionId,
)
from credential_vault.domain.value_objects.states import CredentialState
from credential_vault.infrastructure.persistence.models.audit_entry_model import AuditEntryModel
from credential_vault.infrastructure.persistence.models.audit_log_model import AuditLogModel

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession


def _entry_to_domain(row: AuditEntryModel) -> AuditEntry:
    return AuditEntry(
        entry_id=AuditEntryId(row.id),
        audit_log_id=AuditLogId(row.audit_log_id),
        credential_id=CredentialId(row.credential_id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        operation=AuditOperation(row.operation),
        outcome=AuditOutcome(row.outcome),
        principal_id=PrincipalId(row.principal_id),
        occurred_at=row.occurred_at,
        version_id=VersionId(row.version_id) if row.version_id is not None else None,
        client_ip=row.client_ip,
        request_id=row.request_id,
        detail=row.detail,
        state_before=(CredentialState(row.state_before) if row.state_before is not None else None),
        state_after=(CredentialState(row.state_after) if row.state_after is not None else None),
    )


class PgAuditLogRepository(IAuditLogRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, audit_log: AuditLog) -> None:
        model = AuditLogModel(
            id=audit_log.audit_log_id.value,
            credential_id=audit_log.credential_id.value,
            tenant_id=audit_log.tenant_id.value,
            created_at=audit_log.created_at,
        )
        self._session.add(model)
        await self._session.flush()

    async def get_by_credential(self, credential_id: CredentialId, tenant_id: TenantId) -> AuditLog:
        stmt = select(AuditLogModel).where(
            AuditLogModel.credential_id == credential_id.value,
            AuditLogModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            raise CredentialNotFound(credential_id, tenant_id)
        return AuditLog(
            audit_log_id=AuditLogId(row.id),
            credential_id=CredentialId(row.credential_id),
            tenant_id=TenantId.from_uuid(row.tenant_id),
            entries=[],
            created_at=row.created_at,
            version=0,
        )

    async def append_entry(
        self,
        audit_log_id: AuditLogId,
        entry: AuditEntry,
        tenant_id: TenantId,
    ) -> None:
        _ = tenant_id
        model = AuditEntryModel(
            id=entry.entry_id.value,
            audit_log_id=audit_log_id.value,
            credential_id=entry.credential_id.value,
            tenant_id=entry.tenant_id.value,
            operation=entry.operation.value,
            outcome=entry.outcome.value,
            principal_id=entry.principal_id.value,
            occurred_at=entry.occurred_at,
            detail=entry.detail,
            client_ip=entry.client_ip,
            request_id=entry.request_id,
            version_id=entry.version_id.value if entry.version_id is not None else None,
            state_before=(entry.state_before.value if entry.state_before is not None else None),
            state_after=entry.state_after.value if entry.state_after is not None else None,
        )
        self._session.add(model)
        await self._session.flush()

    async def list_entries(
        self,
        audit_log_id: AuditLogId,
        tenant_id: TenantId,
        since: datetime | None = None,
        operations: list[AuditOperation] | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEntry]:
        stmt = select(AuditEntryModel).where(
            AuditEntryModel.audit_log_id == audit_log_id.value,
            AuditEntryModel.tenant_id == tenant_id.value,
        )
        if since is not None:
            stmt = stmt.where(AuditEntryModel.occurred_at >= since)
        if operations is not None:
            stmt = stmt.where(AuditEntryModel.operation.in_([op.value for op in operations]))
        stmt = stmt.order_by(AuditEntryModel.occurred_at.desc()).limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return [_entry_to_domain(row) for row in result.scalars().all()]
