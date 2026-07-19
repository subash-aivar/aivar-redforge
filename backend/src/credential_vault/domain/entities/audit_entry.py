"""Immutable AuditEntry entity belonging to AuditLog."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from credential_vault.domain.exceptions.domain_exceptions import InvalidArgument

if TYPE_CHECKING:
    from datetime import datetime

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


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """
    Immutable after creation. All fields set in constructor.
    Never deleted. Never modified.
    """

    entry_id: AuditEntryId
    audit_log_id: AuditLogId
    credential_id: CredentialId
    tenant_id: TenantId
    operation: AuditOperation
    outcome: AuditOutcome
    principal_id: PrincipalId
    occurred_at: datetime
    version_id: VersionId | None
    client_ip: str | None
    request_id: str | None
    detail: str | None
    state_before: CredentialState | None
    state_after: CredentialState | None

    def __post_init__(self) -> None:
        if self.detail is not None and len(self.detail) > 4096:
            raise InvalidArgument("detail", "audit detail max 4096 chars")
