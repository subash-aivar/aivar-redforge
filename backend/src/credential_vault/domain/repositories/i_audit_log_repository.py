"""IAuditLogRepository ABC."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from credential_vault.domain.aggregates.audit_log import AuditLog
    from credential_vault.domain.entities.audit_entry import AuditEntry
    from credential_vault.domain.value_objects.audit_types import AuditOperation
    from credential_vault.domain.value_objects.identifiers import (
        AuditLogId,
        CredentialId,
        TenantId,
    )


class IAuditLogRepository(ABC):
    @abstractmethod
    async def save(self, audit_log: AuditLog) -> None:
        """Persist audit log aggregate."""

    @abstractmethod
    async def get_by_credential(
        self, credential_id: CredentialId, tenant_id: TenantId
    ) -> AuditLog:
        """Raises CredentialNotFound if no log for this credential."""

    @abstractmethod
    async def append_entry(
        self,
        audit_log_id: AuditLogId,
        entry: AuditEntry,
        tenant_id: TenantId,
    ) -> None:
        """Append-only. Raises on any failure — fail-closed contract."""

    @abstractmethod
    async def list_entries(
        self,
        audit_log_id: AuditLogId,
        tenant_id: TenantId,
        since: datetime | None = None,
        operations: list[AuditOperation] | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """List audit entries with optional filters."""
