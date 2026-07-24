from __future__ import annotations

import pytest

from ai_security.domain.value_objects.identifiers import (
    ConversationId,
    DeploymentId,
    EvaluationId,
    ModelId,
    PolicyId,
    PromptId,
    ProviderId,
    TargetId,
    TenantId,
)


@pytest.mark.parametrize(
    "id_cls",
    [TargetId, ModelId, DeploymentId, ProviderId, ConversationId, PromptId, PolicyId, EvaluationId],
)
def test_identifier_generate_and_str(id_cls) -> None:
    a = id_cls.generate()
    b = id_cls.generate()
    assert a != b
    assert isinstance(str(a), str)
    assert str(a) == str(a.value)


@pytest.mark.parametrize(
    "id_cls",
    [TargetId, ModelId, DeploymentId, ProviderId, ConversationId, PromptId, PolicyId, EvaluationId],
)
def test_identifier_is_frozen(id_cls) -> None:
    identifier = id_cls.generate()
    with pytest.raises(AttributeError):
        identifier.value = identifier.value  # type: ignore[misc]


def test_tenant_id_is_shared_kernel_entity_id() -> None:
    tenant_id = TenantId.generate()
    assert str(tenant_id)
    assert TenantId.generate() != tenant_id
