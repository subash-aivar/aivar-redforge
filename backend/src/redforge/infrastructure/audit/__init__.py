"""Immutable audit logging infrastructure.

Captures security-relevant events for compliance and forensics.
Designed for future SIEM integration (Splunk, Datadog, ELK).

Events are append-only and include:
- Authentication (login, register, token refresh, failures)
- Organization lifecycle (create, rename, deactivate)
- User management (role changes, status changes)
- AI Target management (register, deactivate)
- Validation execution (schedule, complete, cancel)
- Policy updates (create, modify, delete)
- Provider configuration changes
- Administrative actions

Architecture: Protocol-based. Swap InMemoryAuditLog for
PostgreSQL, Kafka, or cloud SIEM without changing business logic.
"""

from redforge.infrastructure.audit.contracts import AuditEntry, AuditLog
from redforge.infrastructure.audit.logger import InMemoryAuditLog, StructlogAuditLog

__all__ = ["AuditEntry", "AuditLog", "InMemoryAuditLog", "StructlogAuditLog"]
