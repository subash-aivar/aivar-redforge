"""Tests for AuditEntry entity."""

from __future__ import annotations

from uuid import uuid4

import pytest

from credential_vault.domain.entities.audit_entry import AuditEntry
from credential_vault.domain.exceptions.domain_exceptions import InvalidArgument
from credential_vault.domain.value_objects.audit_types import AuditOperation, AuditOutcome
from credential_vault.domain.value_objects.identifiers import AuditEntryId, AuditLogId


class TestAuditEntry:
    def test_valid_entry(
        self, credential_id, tenant_id, principal_id, version_id, now
    ) -> None:
        entry = AuditEntry(
            entry_id=AuditEntryId(uuid4()),
            audit_log_id=AuditLogId(uuid4()),
            credential_id=credential_id,
            tenant_id=tenant_id,
            operation=AuditOperation.ACCESSED,
            outcome=AuditOutcome.SUCCESS,
            principal_id=principal_id,
            occurred_at=now,
            version_id=version_id,
            client_ip="127.0.0.1",
            request_id="req-1",
            detail="read secret",
            state_before=None,
            state_after=None,
        )
        assert entry.operation == AuditOperation.ACCESSED

    def test_detail_too_long(
        self, credential_id, tenant_id, principal_id, now
    ) -> None:
        with pytest.raises(InvalidArgument, match="detail"):
            AuditEntry(
                entry_id=AuditEntryId(uuid4()),
                audit_log_id=AuditLogId(uuid4()),
                credential_id=credential_id,
                tenant_id=tenant_id,
                operation=AuditOperation.ACCESSED,
                outcome=AuditOutcome.SUCCESS,
                principal_id=principal_id,
                occurred_at=now,
                version_id=None,
                client_ip=None,
                request_id=None,
                detail="x" * 4097,
                state_before=None,
                state_after=None,
            )
