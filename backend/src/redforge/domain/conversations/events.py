"""Domain events for the Conversation bounded context."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime  # noqa: TC003 — used in frozen dataclass fields

from redforge.shared.timestamps import utc_now


def _now() -> datetime:
    return utc_now()


@dataclass(frozen=True, slots=True)
class ConversationEvent:
    session_id: str
    organization_id: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ConversationSessionCreated(ConversationEvent):
    strategy_type: str = ""
    attack_category: str = ""
    max_turns: int = 0


@dataclass(frozen=True, slots=True)
class ConversationSessionStarted(ConversationEvent):
    pass


@dataclass(frozen=True, slots=True)
class ConversationTurnRecorded(ConversationEvent):
    turn_number: int = 0
    decision: str = ""
    evaluation_outcome: str = ""


@dataclass(frozen=True, slots=True)
class ConversationSessionCompleted(ConversationEvent):
    outcome: str = ""
    total_turns: int = 0
    success_rate: float = 0.0


@dataclass(frozen=True, slots=True)
class ConversationSessionFailed(ConversationEvent):
    reason: str = ""


@dataclass(frozen=True, slots=True)
class ConversationSessionCancelled(ConversationEvent):
    reason: str = ""


@dataclass(frozen=True, slots=True)
class ConversationBudgetExhausted(ConversationEvent):
    exhaustion_reason: str = ""
    turns_completed: int = 0
