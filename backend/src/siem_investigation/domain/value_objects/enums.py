"""Closed enums for the siem_investigation bounded context (M37 §7)."""

from __future__ import annotations

from enum import StrEnum


class TimelineScopeType(StrEnum):
    """What an `InvestigationTimeline` is scoped to (M37 §7)."""

    ENTITY = "entity"
    ALERT = "alert"
    INCIDENT = "incident"


class InvestigationEngineRole(StrEnum):
    """RBAC scopes for siem_investigation's application layer (M37 §16
    — extends the existing platform RBAC, no parallel model)."""

    VIEWER = "siem_investigation:viewer"
    EXECUTOR = "siem_investigation:execute"
    ADMIN = "siem_investigation:admin"
