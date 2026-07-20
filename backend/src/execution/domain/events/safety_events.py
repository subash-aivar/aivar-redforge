"""Kill switch and journal domain events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from execution.domain.events.base import BaseDomainEvent

if TYPE_CHECKING:
    from execution.domain.value_objects.enums import KillSwitchArmedState, KillSwitchScope


@dataclass(frozen=True, slots=True, kw_only=True)
class KillSwitchTriggered(BaseDomainEvent):
    scope: KillSwitchScope
    scope_ref: str
    authority_ref: str
    reason: str
    trigger_hash: str
    previous_state: KillSwitchArmedState


@dataclass(frozen=True, slots=True, kw_only=True)
class KillSwitchReleased(BaseDomainEvent):
    scope: KillSwitchScope
    scope_ref: str
    releasing_authority_ref: str
    countersigning_authority_ref: str | None
    previous_state: KillSwitchArmedState


@dataclass(frozen=True, slots=True, kw_only=True)
class KillSwitchReArmed(BaseDomainEvent):
    scope: KillSwitchScope
    scope_ref: str
    authority_ref: str
    previous_state: KillSwitchArmedState


@dataclass(frozen=True, slots=True, kw_only=True)
class JournalChainIntegrityFailed(BaseDomainEvent):
    journal_id: str
    engagement_id: str
    broken_at_sequence: int | None
    detail: str


@dataclass(frozen=True, slots=True, kw_only=True)
class JournalCreated(BaseDomainEvent):
    engagement_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class JournalEntryAppended(BaseDomainEvent):
    journal_id: str
    entry_id: str
    entry_type: str
    sequence_number: int
    entry_hash: str
