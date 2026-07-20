"""Journal entry entity — append-only, immutable after creation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from execution.domain.value_objects.enums import JournalEntryType
    from execution.domain.value_objects.identifiers import JournalEntryId, OperatorId


@dataclass(slots=True)
class JournalEntry:
    """Immutable journal entry; never update or delete after append."""

    entry_id: JournalEntryId
    entry_type: JournalEntryType
    sequence_number: int
    entry_hash: str
    previous_entry_hash: str
    content: str
    attribution: OperatorId | None
    system_attribution: str | None
    occurred_at: datetime
    corrects_ref: JournalEntryId | None = None

    @staticmethod
    def compute_entry_hash(previous_entry_hash: str, entry_content: str) -> str:
        payload = f"{previous_entry_hash}{entry_content}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def content_for_hash(self) -> str:
        attr = str(self.attribution) if self.attribution is not None else (
            self.system_attribution or "system"
        )
        return (
            f"{self.entry_type.value}|{self.sequence_number}|{self.content}|"
            f"{attr}|{self.occurred_at.isoformat()}"
        )
