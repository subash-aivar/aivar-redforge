"""Domain event produced by the minimal `Conversation` value object
(M47A). `Conversation` here is a bare registration-style placeholder —
id/tenant/state/created_at only, no message content, no prompt logic."""

from __future__ import annotations

from dataclasses import dataclass

from ai_security.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class ConversationCreated(BaseDomainEvent):
    state: str = ""
