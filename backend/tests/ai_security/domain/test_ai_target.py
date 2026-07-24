from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ai_security.domain.aggregates.ai_target import AiTarget
from ai_security.domain.events.ai_target_events import AiTargetRegistered
from ai_security.domain.exceptions.domain_exceptions import EmptyDisplayNameError, TenantMismatch
from ai_security.domain.value_objects.enums import TargetType
from ai_security.domain.value_objects.identifiers import TargetId, TenantId

NOW = datetime.now(UTC)


def _register(**overrides) -> AiTarget:
    defaults = {
        "target_id": TargetId.generate(),
        "tenant_id": TenantId.generate(),
        "name": "prod-chatbot",
        "target_type": TargetType.CHATBOT,
        "now": NOW,
    }
    defaults.update(overrides)
    return AiTarget.register(**defaults)


def test_register_sets_fields_and_emits_event() -> None:
    target = _register()
    assert target.name == "prod-chatbot"
    assert target.target_type == TargetType.CHATBOT
    events = target.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], AiTargetRegistered)
    assert events[0].target_type == str(TargetType.CHATBOT)


def test_pop_events_drains_and_is_idempotent() -> None:
    target = _register()
    target.pop_events()
    assert target.pop_events() == []


def test_register_rejects_empty_name() -> None:
    with pytest.raises(EmptyDisplayNameError):
        _register(name="   ")


def test_tenant_mismatch_raised_by_helper() -> None:
    target = _register()
    other_tenant = TenantId.generate()
    with pytest.raises(TenantMismatch):
        target._assert_tenant(other_tenant)
