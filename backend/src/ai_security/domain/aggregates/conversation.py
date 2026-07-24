"""Conversation — a minimal placeholder entity (M47A).

Deliberately bare: id/tenant/state/created_at only. No message
content, no prompt logic, no evaluation semantics — those are
explicitly out of scope until a later milestone. Modeled as a light
entity (not a value object) only because it needs identity and emits
`ConversationCreated`; it owns no behavior beyond construction."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_security.domain.events.conversation_events import ConversationCreated
from ai_security.domain.value_objects.enums import ConversationState

if TYPE_CHECKING:
    from datetime import datetime

    from ai_security.domain.events.base import BaseDomainEvent
    from ai_security.domain.value_objects.identifiers import ConversationId, TargetId, TenantId


class Conversation:
    __slots__ = (
        "_pending_events",
        "conversation_id",
        "created_at",
        "state",
        "target_id",
        "tenant_id",
    )

    def __init__(
        self,
        conversation_id: ConversationId,
        tenant_id: TenantId,
        target_id: TargetId,
        created_at: datetime,
        state: ConversationState = ConversationState.ACTIVE,
    ) -> None:
        self.conversation_id = conversation_id
        self.tenant_id = tenant_id
        self.target_id = target_id
        self.created_at = created_at
        self.state = state
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    @classmethod
    def create(
        cls,
        conversation_id: ConversationId,
        tenant_id: TenantId,
        target_id: TargetId,
        now: datetime,
    ) -> Conversation:
        conversation = cls(
            conversation_id=conversation_id,
            tenant_id=tenant_id,
            target_id=target_id,
            created_at=now,
        )
        conversation._emit(
            ConversationCreated(
                tenant_id=str(tenant_id),
                aggregate_id=str(conversation_id),
                aggregate_type="Conversation",
                occurred_at=now,
                state=str(conversation.state),
            )
        )
        return conversation
