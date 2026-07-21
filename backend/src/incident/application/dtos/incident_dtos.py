from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class IncidentDTO:
    incident_id: str
    tenant_id: str
    title: str
    description: str
    phase: str
    severity: str
    trigger_type: str
    classified_at: str | None
    contained_at: str | None
    eradicated_at: str | None
    recovered_at: str | None
    closed_at: str | None
    resolution_type: str | None
    timeline: list[dict[str, Any]]


@dataclass(frozen=True, slots=True)
class ContainmentActionDTO:
    action_id: str
    incident_id: str
    action_type: str
    status: str
    authorization_level_required: str
    authorized_by: str | None


@dataclass(frozen=True, slots=True)
class CommunicationLogEntryDTO:
    entry_id: str
    content: str
    author: str
    logged_at: str
    entry_sequence: int
    entry_hash: str
    prev_hash: str
