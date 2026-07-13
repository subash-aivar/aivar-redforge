"""Audit log implementations.

Two implementations:
- InMemoryAuditLog: For testing. Stores entries in a list.
- StructlogAuditLog: For production. Writes structured JSON to stdout/file.
  Can be picked up by log aggregators (Datadog, ELK, CloudWatch).

Future implementations:
- PostgreSQLAuditLog: Persistent append-only table
- KafkaAuditLog: Stream to event bus for real-time SIEM
"""

from __future__ import annotations

from datetime import datetime

from redforge.core.logging import get_logger
from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry

logger = get_logger("redforge.audit")


class StructlogAuditLog:
    """Production audit log that emits structured JSON via structlog.

    Events are written to stdout in JSON format, ready for ingestion
    by log aggregators (Datadog Agent, Fluentd, CloudWatch Logs).

    Append-only by design — structlog output is immutable once written.
    """

    async def record(self, entry: AuditEntry) -> None:
        """Emit an audit event as a structured log entry."""
        logger.info(
            "audit_event",
            audit_action=entry.action.value,
            actor_id=entry.actor_id,
            resource_type=entry.resource_type,
            resource_id=entry.resource_id,
            ip_address=entry.ip_address,
            correlation_id=entry.correlation_id,
            timestamp=entry.timestamp.isoformat(),
            **entry.metadata,
        )

    async def query(
        self,
        *,
        actor_id: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        action: AuditAction | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Not supported for structlog implementation.

        Use a log aggregator's query interface instead.
        Returns empty list — production queries go through SIEM.
        """
        return []


class InMemoryAuditLog:
    """In-memory audit log for testing.

    Stores entries in a list for assertion in tests.
    """

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    async def record(self, entry: AuditEntry) -> None:
        """Append entry to in-memory store."""
        self._entries.append(entry)

    async def query(
        self,
        *,
        actor_id: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        action: AuditAction | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Filter and return entries from in-memory store."""
        results = self._entries

        if actor_id is not None:
            results = [e for e in results if e.actor_id == actor_id]
        if resource_type is not None:
            results = [e for e in results if e.resource_type == resource_type]
        if resource_id is not None:
            results = [e for e in results if e.resource_id == resource_id]
        if action is not None:
            results = [e for e in results if e.action == action]
        if since is not None:
            results = [e for e in results if e.timestamp >= since]

        # Newest first
        results = sorted(results, key=lambda e: e.timestamp, reverse=True)
        return results[:limit]

    @property
    def entries(self) -> list[AuditEntry]:
        """Direct access to entries for test assertions."""
        return list(self._entries)

    def clear(self) -> None:
        """Clear all entries (test utility)."""
        self._entries.clear()
