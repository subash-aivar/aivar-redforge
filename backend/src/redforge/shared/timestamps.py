"""Audit timestamp primitives for domain entities.

Every entity in RedForge carries creation and modification timestamps.
These are represented as UTC-aware datetime values and encapsulated
in a dataclass for consistent usage across all bounded contexts.

Usage:
    from redforge.shared import utc_now, AuditTimestamps

    timestamps = AuditTimestamps.create()
    updated = timestamps.mark_updated()
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime.

    Centralizing this call ensures consistent timestamp generation
    across the entire domain and makes time-dependent logic testable
    by allowing this function to be patched in tests.
    """
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class AuditTimestamps:
    """Immutable audit timestamps carried by every domain entity.

    Attributes:
        created_at: When the entity was first created (never changes).
        updated_at: When the entity was last modified (advances on mutation).
    """

    created_at: datetime
    updated_at: datetime

    @classmethod
    def create(cls) -> AuditTimestamps:
        """Create timestamps for a new entity. Both fields set to now."""
        now = utc_now()
        return cls(created_at=now, updated_at=now)

    def mark_updated(self) -> AuditTimestamps:
        """Return new timestamps with updated_at advanced to now.

        AuditTimestamps is immutable — this returns a new instance
        while preserving the original created_at.
        """
        return AuditTimestamps(created_at=self.created_at, updated_at=utc_now())
