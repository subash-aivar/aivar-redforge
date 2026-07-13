"""Domain events for the Evidence bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class EvidenceEvent:
    """Base class for all Evidence domain events."""

    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class EvidenceRecorded(EvidenceEvent):
    """A new piece of evidence was recorded."""

    evidence_id: str
    run_id: str
    target_id: str
    result: str


@dataclass(frozen=True, slots=True)
class EvidenceFinalized(EvidenceEvent):
    """Evidence was finalized (sealed, immutable from this point)."""

    evidence_id: str
    run_id: str


@dataclass(frozen=True, slots=True)
class ArtifactAttached(EvidenceEvent):
    """An artifact was attached to evidence (before finalization)."""

    evidence_id: str
    artifact_id: str
    artifact_name: str


@dataclass(frozen=True, slots=True)
class EvidenceArchived(EvidenceEvent):
    """Evidence was archived (moved to cold storage)."""

    evidence_id: str


def _now() -> datetime:
    """Internal helper for event timestamp generation."""
    return utc_now()
