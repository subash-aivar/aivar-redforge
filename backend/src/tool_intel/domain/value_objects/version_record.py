"""VersionRecord — append-only version-history entry for Tool."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from tool_intel.domain.exceptions.domain_exceptions import EmptyIdentifierError

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class VersionRecord:
    version: int
    changed_at: datetime
    change_summary: str
    source: str

    def __post_init__(self) -> None:
        if self.version < 1:
            raise ValueError("version must be >= 1")
        if not self.change_summary.strip():
            raise EmptyIdentifierError("change_summary")
        if not self.source.strip():
            raise EmptyIdentifierError("source")
