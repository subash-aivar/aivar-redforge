"""Tests for AuditLog aggregate."""

from __future__ import annotations

from uuid import uuid4

import pytest

from credential_vault.domain.aggregates.audit_log import AuditLog
from credential_vault.domain.entities.audit_entry import AuditEntry
from credential_vault.domain.exceptions.domain_exceptions import TenantMismatch
from credential_vault.domain.value_objects.audit_types import AuditOperation, AuditOutcome
from credential_vault.domain.value_objects.identifiers import AuditEntryId, AuditLogId, CredentialId


class TestAuditLog:
    def test_create(self, credential_id, tenant_id, now) -> None:
        log = AuditLog.create(
            audit_log_id=AuditLogId(uuid4()),
            credential_id=credential_id,
            tenant_id=tenant_id,
            now=now,
        )
        assert log.entries == []
        assert log.version == 0

    def test_append_entry(
        self, credential_id, tenant_id, principal_id, version_id, now
    ) -> None:
        log_id = AuditLogId(uuid4())
        log = AuditLog.create(
            audit_log_id=log_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            now=now,
        )
        entry = AuditEntry(
            entry_id=AuditEntryId(uuid4()),
            audit_log_id=log_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            operation=AuditOperation.ACCESSED,
            outcome=AuditOutcome.SUCCESS,
            principal_id=principal_id,
            occurred_at=now,
            version_id=version_id,
            client_ip="10.0.0.1",
            request_id="req-1",
            detail=None,
            state_before=None,
            state_after=None,
        )
        log.append(entry, now)
        assert len(log.entries) == 1
        assert log.version == 1

    def test_append_rejects_credential_mismatch(
        self, credential_id, tenant_id, other_tenant_id, principal_id, now
    ) -> None:
        log_id = AuditLogId(uuid4())
        log = AuditLog.create(
            audit_log_id=log_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            now=now,
        )
        other_credential_id = CredentialId(uuid4())
        entry = AuditEntry(
            entry_id=AuditEntryId(uuid4()),
            audit_log_id=log_id,
            credential_id=other_credential_id,
            tenant_id=other_tenant_id,
            operation=AuditOperation.ACCESSED,
            outcome=AuditOutcome.SUCCESS,
            principal_id=principal_id,
            occurred_at=now,
            version_id=None,
            client_ip=None,
            request_id=None,
            detail=None,
            state_before=None,
            state_after=None,
        )
        with pytest.raises(TenantMismatch):
            log.append(entry, now)

    def test_pop_events_idempotent(self, credential_id, tenant_id, now) -> None:
        log = AuditLog.create(
            audit_log_id=AuditLogId(uuid4()),
            credential_id=credential_id,
            tenant_id=tenant_id,
            now=now,
        )
        assert log.pop_events() == []
        assert log.pop_events() == []
