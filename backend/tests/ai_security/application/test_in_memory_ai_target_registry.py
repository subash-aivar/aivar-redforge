from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ai_security.application.exceptions import DuplicateAiTargetError
from ai_security.application.registry.in_memory_ai_target_registry import (
    InMemoryAiTargetRegistry,
)
from ai_security.domain.aggregates.ai_target import AiTarget
from ai_security.domain.value_objects.enums import TargetType
from ai_security.domain.value_objects.identifiers import TargetId, TenantId

NOW = datetime.now(UTC)


def _target(tenant_id: TenantId | None = None) -> AiTarget:
    return AiTarget.register(
        target_id=TargetId.generate(),
        tenant_id=tenant_id or TenantId.generate(),
        name="target-a",
        target_type=TargetType.AGENT,
        now=NOW,
    )


def test_register_and_get() -> None:
    registry = InMemoryAiTargetRegistry()
    target = _target()
    registry.register(target)
    assert registry.get(target.tenant_id, target.target_id) is target


def test_duplicate_register_raises() -> None:
    registry = InMemoryAiTargetRegistry()
    target = _target()
    registry.register(target)
    with pytest.raises(DuplicateAiTargetError):
        registry.register(target)


def test_get_wrong_tenant_returns_none() -> None:
    registry = InMemoryAiTargetRegistry()
    target = _target()
    registry.register(target)
    assert registry.get(TenantId.generate(), target.target_id) is None


def test_get_unknown_id_returns_none() -> None:
    registry = InMemoryAiTargetRegistry()
    assert registry.get(TenantId.generate(), TargetId.generate()) is None


def test_list_is_tenant_isolated() -> None:
    registry = InMemoryAiTargetRegistry()
    tenant_a = TenantId.generate()
    tenant_b = TenantId.generate()
    target_a1 = _target(tenant_a)
    target_a2 = _target(tenant_a)
    target_b1 = _target(tenant_b)
    registry.register(target_a1)
    registry.register(target_a2)
    registry.register(target_b1)

    result_a = registry.list(tenant_a)
    result_b = registry.list(tenant_b)

    assert set(result_a) == {target_a1, target_a2}
    assert set(result_b) == {target_b1}


def test_list_empty_for_unknown_tenant() -> None:
    registry = InMemoryAiTargetRegistry()
    assert registry.list(TenantId.generate()) == ()
