from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ai_security.domain.aggregates.guardrail_policy import GuardrailPolicy
from ai_security.domain.events.guardrail_policy_events import GuardrailAssigned
from ai_security.domain.exceptions.domain_exceptions import EmptyDisplayNameError, TenantMismatch
from ai_security.domain.value_objects.identifiers import PolicyId, TargetId, TenantId

NOW = datetime.now(UTC)


def _create(**overrides) -> GuardrailPolicy:
    defaults = {
        "policy_id": PolicyId.generate(),
        "tenant_id": TenantId.generate(),
        "name": "pii-baseline",
        "description": "Baseline PII handling metadata policy",
        "now": NOW,
    }
    defaults.update(overrides)
    return GuardrailPolicy.create(**defaults)


def test_create_sets_fields_no_events() -> None:
    policy = _create()
    assert policy.name == "pii-baseline"
    assert policy.assigned_target_ids == ()
    assert policy.pop_events() == []


def test_create_rejects_empty_name() -> None:
    with pytest.raises(EmptyDisplayNameError):
        _create(name="")


def test_assign_to_target_appends_and_emits_event() -> None:
    policy = _create()
    target_id = TargetId.generate()
    policy.assign_to_target(policy.tenant_id, target_id, NOW)
    assert target_id in policy.assigned_target_ids
    events = policy.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], GuardrailAssigned)
    assert events[0].target_id == str(target_id)


def test_assign_wrong_tenant_raises() -> None:
    policy = _create()
    with pytest.raises(TenantMismatch):
        policy.assign_to_target(TenantId.generate(), TargetId.generate(), NOW)
