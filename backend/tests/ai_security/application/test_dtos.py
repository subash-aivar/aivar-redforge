from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from ai_security.application.dtos.ai_deployment_dto import AiDeploymentDTO
from ai_security.application.dtos.ai_target_dto import AiTargetDTO
from ai_security.application.dtos.guardrail_policy_dto import GuardrailPolicyDTO

NOW = datetime.now(UTC)


def test_ai_target_dto_immutable() -> None:
    dto = AiTargetDTO(
        target_id="t1", tenant_id="ten1", name="target-a", target_type="agent", registered_at=NOW
    )
    assert dataclasses.is_dataclass(dto)
    with pytest.raises(dataclasses.FrozenInstanceError):
        dto.name = "other"  # type: ignore[misc]


def test_ai_deployment_dto_immutable() -> None:
    dto = AiDeploymentDTO(
        deployment_id="d1",
        tenant_id="ten1",
        target_id="t1",
        model_family="gpt",
        model_version="v1",
        provider_id="p1",
        endpoint_url="https://api.example.com",
        status="pending",
        created_at=NOW,
        updated_at=NOW,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        dto.status = "active"  # type: ignore[misc]


def test_guardrail_policy_dto_immutable_and_default_targets() -> None:
    dto = GuardrailPolicyDTO(
        policy_id="p1", tenant_id="ten1", name="policy-a", description="desc", created_at=NOW
    )
    assert dto.assigned_target_ids == ()
    with pytest.raises(dataclasses.FrozenInstanceError):
        dto.name = "other"  # type: ignore[misc]
