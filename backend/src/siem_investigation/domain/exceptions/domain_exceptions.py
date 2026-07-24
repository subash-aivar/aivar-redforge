"""Domain exceptions for siem_investigation."""

from __future__ import annotations


class SiemInvestigationDomainError(Exception):
    """Base domain error for siem_investigation."""


class TenantMismatch(SiemInvestigationDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class EmptyScopeRefError(SiemInvestigationDomainError):
    def __init__(self) -> None:
        super().__init__("InvestigationTimeline.scope_ref must be a non-empty string")


class DuplicateTimelineEntryError(SiemInvestigationDomainError):
    def __init__(self, event_id: str) -> None:
        super().__init__(f"TimelineEntry for event_id={event_id!r} already present")
