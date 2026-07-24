"""Closed enums for the siem_alerting bounded context (M37 §8)."""

from __future__ import annotations

from enum import StrEnum


class AlertStatus(StrEnum):
    """`RAISED → (DEDUPLICATED | SUPPRESSED) → ESCALATED → ACKNOWLEDGED
    → CLOSED` (M37 §8)."""

    RAISED = "raised"
    DEDUPLICATED = "deduplicated"
    SUPPRESSED = "suppressed"
    ESCALATED = "escalated"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"


class AlertSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertSourceKind(StrEnum):
    """An alert originates from either a detection match or a
    correlation match (M37 §9's event flow)."""

    DETECTION = "detection"
    CORRELATION = "correlation"


class AlertEngineRole(StrEnum):
    """RBAC scopes for siem_alerting's application layer (M37 §16 —
    extends the existing platform RBAC, no parallel model). Named
    `AlertEngineRole`, not `AlertRole`, to avoid any ambiguity with the
    `Alert` aggregate's own `AlertStatus`/`AlertSeverity` vocabulary."""

    VIEWER = "siem_alerting:viewer"
    EXECUTOR = "siem_alerting:execute"
    ADMIN = "siem_alerting:admin"
