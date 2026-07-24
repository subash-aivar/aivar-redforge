from __future__ import annotations

from datetime import UTC, datetime

from ai_security.domain.aggregates.conversation import Conversation
from ai_security.domain.events.conversation_events import ConversationCreated
from ai_security.domain.value_objects.enums import ConversationState
from ai_security.domain.value_objects.identifiers import ConversationId, TargetId, TenantId

NOW = datetime.now(UTC)


def test_create_is_active_and_emits_event() -> None:
    conversation = Conversation.create(
        conversation_id=ConversationId.generate(),
        tenant_id=TenantId.generate(),
        target_id=TargetId.generate(),
        now=NOW,
    )
    assert conversation.state == ConversationState.ACTIVE
    events = conversation.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], ConversationCreated)
    assert events[0].state == str(ConversationState.ACTIVE)


def test_pop_events_drains() -> None:
    conversation = Conversation.create(
        conversation_id=ConversationId.generate(),
        tenant_id=TenantId.generate(),
        target_id=TargetId.generate(),
        now=NOW,
    )
    conversation.pop_events()
    assert conversation.pop_events() == []
