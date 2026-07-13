"""Unit tests for audit logging infrastructure."""

from datetime import UTC, datetime, timedelta

import pytest

from redforge.infrastructure.audit import InMemoryAuditLog
from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry


class TestInMemoryAuditLog:
    """Tests for in-memory audit log (used in test infrastructure)."""

    @pytest.fixture
    def audit_log(self) -> InMemoryAuditLog:
        return InMemoryAuditLog()

    async def test_record_appends_entry(self, audit_log: InMemoryAuditLog) -> None:
        entry = AuditEntry(
            action=AuditAction.AUTH_LOGIN,
            actor_id="user-123",
            resource_type="user",
            resource_id="user-123",
            ip_address="192.168.1.1",
        )
        await audit_log.record(entry)
        assert len(audit_log.entries) == 1
        assert audit_log.entries[0].action == AuditAction.AUTH_LOGIN

    async def test_entries_are_immutable(self, audit_log: InMemoryAuditLog) -> None:
        entry = AuditEntry(
            action=AuditAction.ORG_CREATED,
            actor_id="admin",
            resource_type="organization",
            resource_id="org-1",
        )
        await audit_log.record(entry)
        # Frozen dataclass — cannot modify
        with pytest.raises(AttributeError):
            entry.actor_id = "hacker"  # type: ignore[misc]

    async def test_query_by_actor(self, audit_log: InMemoryAuditLog) -> None:
        await audit_log.record(AuditEntry(
            action=AuditAction.AUTH_LOGIN, actor_id="alice",
            resource_type="user", resource_id="alice",
        ))
        await audit_log.record(AuditEntry(
            action=AuditAction.AUTH_LOGIN, actor_id="bob",
            resource_type="user", resource_id="bob",
        ))
        results = await audit_log.query(actor_id="alice")
        assert len(results) == 1
        assert results[0].actor_id == "alice"

    async def test_query_by_action(self, audit_log: InMemoryAuditLog) -> None:
        await audit_log.record(AuditEntry(
            action=AuditAction.AUTH_LOGIN, actor_id="user-1",
            resource_type="user", resource_id="user-1",
        ))
        await audit_log.record(AuditEntry(
            action=AuditAction.AUTH_LOGIN_FAILED, actor_id="user-2",
            resource_type="user", resource_id="user-2",
        ))
        results = await audit_log.query(action=AuditAction.AUTH_LOGIN_FAILED)
        assert len(results) == 1

    async def test_query_by_resource(self, audit_log: InMemoryAuditLog) -> None:
        await audit_log.record(AuditEntry(
            action=AuditAction.ORG_CREATED, actor_id="admin",
            resource_type="organization", resource_id="org-1",
        ))
        await audit_log.record(AuditEntry(
            action=AuditAction.TARGET_REGISTERED, actor_id="admin",
            resource_type="ai_target", resource_id="target-1",
        ))
        results = await audit_log.query(resource_type="organization")
        assert len(results) == 1

    async def test_query_since_timestamp(self, audit_log: InMemoryAuditLog) -> None:
        old = AuditEntry(
            action=AuditAction.AUTH_LOGIN, actor_id="user",
            resource_type="user", resource_id="user",
            timestamp=datetime.now(UTC) - timedelta(hours=2),
        )
        recent = AuditEntry(
            action=AuditAction.AUTH_LOGIN, actor_id="user",
            resource_type="user", resource_id="user",
            timestamp=datetime.now(UTC),
        )
        await audit_log.record(old)
        await audit_log.record(recent)

        cutoff = datetime.now(UTC) - timedelta(hours=1)
        results = await audit_log.query(since=cutoff)
        assert len(results) == 1

    async def test_query_returns_newest_first(self, audit_log: InMemoryAuditLog) -> None:
        for i in range(5):
            await audit_log.record(AuditEntry(
                action=AuditAction.AUTH_LOGIN, actor_id=f"user-{i}",
                resource_type="user", resource_id=f"user-{i}",
                timestamp=datetime.now(UTC) + timedelta(seconds=i),
            ))
        results = await audit_log.query()
        # Should be in reverse chronological order
        assert results[0].actor_id == "user-4"
        assert results[-1].actor_id == "user-0"

    async def test_query_respects_limit(self, audit_log: InMemoryAuditLog) -> None:
        for i in range(10):
            await audit_log.record(AuditEntry(
                action=AuditAction.AUTH_LOGIN, actor_id=f"user-{i}",
                resource_type="user", resource_id=f"user-{i}",
            ))
        results = await audit_log.query(limit=3)
        assert len(results) == 3

    async def test_audit_action_enum_values(self) -> None:
        """Verify key audit actions exist for enterprise compliance."""
        assert AuditAction.AUTH_LOGIN == "auth.login"
        assert AuditAction.ORG_CREATED == "org.created"
        assert AuditAction.VALIDATION_SCHEDULED == "validation.scheduled"
        assert AuditAction.POLICY_DELETED == "policy.deleted"
        assert AuditAction.ADMIN_CONFIG_CHANGED == "admin.config_changed"

    async def test_metadata_in_entry(self, audit_log: InMemoryAuditLog) -> None:
        entry = AuditEntry(
            action=AuditAction.ORG_RENAMED,
            actor_id="admin",
            resource_type="organization",
            resource_id="org-1",
            metadata={"old_name": "Acme", "new_name": "Acme Corp"},
        )
        await audit_log.record(entry)
        stored = audit_log.entries[0]
        assert stored.metadata["old_name"] == "Acme"
        assert stored.metadata["new_name"] == "Acme Corp"
