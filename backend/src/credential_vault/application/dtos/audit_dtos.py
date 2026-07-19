"""Audit entry DTOs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from credential_vault.domain.entities.audit_entry import AuditEntry


@dataclass(frozen=True, slots=True)
class AuditEntryDTO:
    entry_id: str
    audit_log_id: str
    credential_id: str
    tenant_id: str
    operation: str
    outcome: str
    principal_id: str
    occurred_at: str
    detail: str
    client_ip: str | None
    request_id: str | None

    @classmethod
    def from_entity(cls, entry: AuditEntry) -> Self:
        return cls(
            entry_id=str(entry.entry_id),
            audit_log_id=str(entry.audit_log_id),
            credential_id=str(entry.credential_id),
            tenant_id=str(entry.tenant_id),
            operation=entry.operation.value,
            outcome=entry.outcome.value,
            principal_id=str(entry.principal_id),
            occurred_at=entry.occurred_at.isoformat(),
            detail=entry.detail if entry.detail is not None else "",
            client_ip=entry.client_ip,
            request_id=entry.request_id,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "entry_id": self.entry_id,
            "audit_log_id": self.audit_log_id,
            "credential_id": self.credential_id,
            "tenant_id": self.tenant_id,
            "operation": self.operation,
            "outcome": self.outcome,
            "principal_id": self.principal_id,
            "occurred_at": self.occurred_at,
            "detail": self.detail,
            "client_ip": self.client_ip,
            "request_id": self.request_id,
        }
