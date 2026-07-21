"""Hash-chain verification for communication log."""

from __future__ import annotations

from incident.domain.entities.communication_log_entry import IncidentCommunicationLogEntry
from incident.domain.exceptions.domain_exceptions import CommunicationLogTampered


class CommunicationLogService:
    def verify_chain(self, entries: list[IncidentCommunicationLogEntry]) -> None:
        prev = "GENESIS"
        for entry in sorted(entries, key=lambda e: e.entry_sequence):
            if entry.prev_hash != prev:
                raise CommunicationLogTampered("prev_hash mismatch")
            expected = IncidentCommunicationLogEntry.compute_hash(
                prev_hash=entry.prev_hash,
                content=entry.content,
                author=entry.author,
                logged_at=entry.logged_at,
                entry_sequence=entry.entry_sequence,
            )
            if entry.entry_hash != expected:
                raise CommunicationLogTampered("entry_hash mismatch")
            prev = entry.entry_hash
