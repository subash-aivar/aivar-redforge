"""ProvenanceChainEntry — append-only entity within ModelProvenance."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_supply_chain.domain.exceptions.domain_exceptions import ChainEntryImmutable

if TYPE_CHECKING:
    from datetime import datetime

    from ai_supply_chain.domain.value_objects.enums import (
        ChainEntryKind,
        VerificationMethod,
    )
    from ai_supply_chain.domain.value_objects.identifiers import ProvenanceChainEntryId


class ProvenanceChainEntry:
    __slots__ = (
        "entry_id",
        "entry_kind",
        "notes",
        "recorded_at",
        "trust_delegation_note",
        "verification_method",
    )

    def __init__(
        self,
        entry_id: ProvenanceChainEntryId,
        entry_kind: ChainEntryKind,
        recorded_at: datetime,
        verification_method: VerificationMethod | None,
        trust_delegation_note: str,
        notes: str,
    ) -> None:
        self.entry_id = entry_id
        self.entry_kind = entry_kind
        self.recorded_at = recorded_at
        self.verification_method = verification_method
        self.trust_delegation_note = trust_delegation_note
        self.notes = notes

    def mutate(self) -> None:
        raise ChainEntryImmutable()

    def delete(self) -> None:
        raise ChainEntryImmutable()
