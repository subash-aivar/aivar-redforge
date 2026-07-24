from __future__ import annotations

import dataclasses

import pytest

from ai_security.application.commands.ai_deployment_commands import (
    CreateDeploymentCommand,
    UpdateDeploymentCommand,
)
from ai_security.application.commands.ai_target_commands import RegisterAiTargetCommand
from ai_security.application.commands.conversation_commands import CreateConversationCommand
from ai_security.application.commands.guardrail_policy_commands import (
    AssignGuardrailPolicyCommand,
)
from ai_security.application.queries.ai_target_queries import (
    GetAiTargetQuery,
    GetDeploymentQuery,
    ListAiTargetsQuery,
    ListDeploymentsQuery,
)
from ai_security.domain.value_objects.endpoint_url import EndpointUrl
from ai_security.domain.value_objects.enums import DeploymentStatus, ModelFamily, TargetType
from ai_security.domain.value_objects.identifiers import (
    DeploymentId,
    PolicyId,
    ProviderId,
    TargetId,
    TenantId,
)
from ai_security.domain.value_objects.model_version import ModelVersion


def test_register_ai_target_command_is_frozen() -> None:
    cmd = RegisterAiTargetCommand(
        tenant_id=TenantId.generate(), name="target-a", target_type=TargetType.AGENT
    )
    assert dataclasses.is_dataclass(cmd)
    with pytest.raises(dataclasses.FrozenInstanceError):
        cmd.name = "other"  # type: ignore[misc]


def test_create_deployment_command_fields() -> None:
    cmd = CreateDeploymentCommand(
        tenant_id=TenantId.generate(),
        target_id=TargetId.generate(),
        model_family=ModelFamily.CLAUDE,
        model_version=ModelVersion("claude-4"),
        provider_id=ProviderId.generate(),
        endpoint_url=EndpointUrl("https://api.anthropic.com/v1"),
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        cmd.model_version = ModelVersion("claude-5")  # type: ignore[misc]


def test_update_deployment_command_fields() -> None:
    cmd = UpdateDeploymentCommand(
        tenant_id=TenantId.generate(),
        deployment_id=DeploymentId.generate(),
        status=DeploymentStatus.ACTIVE,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        cmd.status = DeploymentStatus.PAUSED  # type: ignore[misc]


def test_assign_guardrail_policy_command_fields() -> None:
    cmd = AssignGuardrailPolicyCommand(
        tenant_id=TenantId.generate(), policy_id=PolicyId.generate(), target_id=TargetId.generate()
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        cmd.policy_id = PolicyId.generate()  # type: ignore[misc]


def test_create_conversation_command_fields() -> None:
    cmd = CreateConversationCommand(tenant_id=TenantId.generate(), target_id=TargetId.generate())
    with pytest.raises(dataclasses.FrozenInstanceError):
        cmd.target_id = TargetId.generate()  # type: ignore[misc]


def test_queries_are_frozen() -> None:
    tenant_id = TenantId.generate()
    get_q = GetAiTargetQuery(tenant_id=tenant_id, target_id=TargetId.generate())
    list_q = ListAiTargetsQuery(tenant_id=tenant_id)
    get_dep_q = GetDeploymentQuery(tenant_id=tenant_id, deployment_id=DeploymentId.generate())
    list_dep_q = ListDeploymentsQuery(tenant_id=tenant_id)
    for q in (get_q, list_q, get_dep_q, list_dep_q):
        assert dataclasses.is_dataclass(q)
    with pytest.raises(dataclasses.FrozenInstanceError):
        get_q.tenant_id = TenantId.generate()  # type: ignore[misc]
