"""Append-only communication log entry with hash chain."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime

from incident.domain.value_objects.enums import CommunicationType
from incident.domain.value_objects.identifiers import (
    CommunicationLogEntryId,
    IncidentId,
    TenantId,
)


@dataclass(frozen=True, slots=True)
class IncidentCommunicationLogEntry:
    entry_id: CommunicationLogEntryId
    tenant_id: TenantId
    incident_id: IncidentId
    content: str
    author: str
    recipient_summary: str
    communication_type: CommunicationType
    logged_at: datetime
    entry_sequence: int
    prev_hash: str
    entry_hash: str

    @staticmethod
    def compute_hash(
        *,
        prev_hash: str,
        content: str,
        author: str,
        logged_at: datetime,
        entry_sequence: int,
    ) -> str:
        payload = f"{prev_hash}|{content}|{author}|{logged_at.isoformat()}|{entry_sequence}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
