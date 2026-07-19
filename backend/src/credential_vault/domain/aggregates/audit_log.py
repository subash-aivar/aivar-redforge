"""AuditLog aggregate root — append-only."""

from __future__ import annotations

from typing import TYPE_CHECKING

from credential_vault.domain.exceptions.domain_exceptions import TenantMismatch

if TYPE_CHECKING:
    from datetime import datetime

    from credential_vault.domain.entities.audit_entry import AuditEntry
    from credential_vault.domain.events.base import BaseDomainEvent
    from credential_vault.domain.value_objects.identifiers import (
        AuditLogId,
        CredentialId,
        TenantId,
    )


class AuditLog:
    """
    Append-only aggregate. No entries may ever be deleted or modified.
    One AuditLog per credential (1:1 relationship).
    """

    __slots__ = (
        "_pending_events",
        "_version",
        "audit_log_id",
        "created_at",
        "credential_id",
        "entries",
        "tenant_id",
    )

    def __init__(
        self,
        audit_log_id: AuditLogId,
        credential_id: CredentialId,
        tenant_id: TenantId,
        entries: list[AuditEntry],
        created_at: datetime,
        version: int,
    ) -> None:
        self.audit_log_id = audit_log_id
        self.credential_id = credential_id
        self.tenant_id = tenant_id
        self.entries = list(entries)
        self.created_at = created_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @classmethod
    def create(
        cls,
        audit_log_id: AuditLogId,
        credential_id: CredentialId,
        tenant_id: TenantId,
        now: datetime,
    ) -> AuditLog:
        return cls(
            audit_log_id=audit_log_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            entries=[],
            created_at=now,
            version=0,
        )

    def append(self, entry: AuditEntry, now: datetime) -> None:
        if entry.credential_id != self.credential_id:
            raise TenantMismatch(
                expected=self.tenant_id,
                actual=entry.tenant_id,
            )
        if entry.tenant_id != self.tenant_id:
            raise TenantMismatch(expected=self.tenant_id, actual=entry.tenant_id)
        _ = now
        self.entries.append(entry)
        self._version += 1

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    @property
    def version(self) -> int:
        return self._version
