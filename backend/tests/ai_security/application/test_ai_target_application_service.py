from __future__ import annotations

from uuid import UUID

import pytest

from ai_security.application.commands.ai_target_commands import RegisterAiTargetCommand
from ai_security.application.exceptions import InvalidDisplayNameError
from ai_security.application.queries.ai_target_queries import (
    GetAiTargetQuery,
    ListAiTargetsQuery,
)
from ai_security.application.registry.in_memory_ai_target_registry import (
    InMemoryAiTargetRegistry,
)
from ai_security.application.services.ai_target_application_service import (
    AiTargetApplicationService,
)
from ai_security.domain.value_objects.enums import TargetType
from ai_security.domain.value_objects.identifiers import TargetId, TenantId


def _service() -> AiTargetApplicationService:
    return AiTargetApplicationService(InMemoryAiTargetRegistry())


def test_register_target_returns_dto() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    dto = service.register_target(
        RegisterAiTargetCommand(tenant_id=tenant_id, name="target-a", target_type=TargetType.AGENT)
    )
    assert dto.name == "target-a"
    assert dto.tenant_id == str(tenant_id)
    assert dto.target_type == str(TargetType.AGENT)


def test_register_target_rejects_empty_name() -> None:
    service = _service()
    with pytest.raises(InvalidDisplayNameError):
        service.register_target(
            RegisterAiTargetCommand(
                tenant_id=TenantId.generate(), name="  ", target_type=TargetType.AGENT
            )
        )


def test_get_target_round_trips() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    dto = service.register_target(
        RegisterAiTargetCommand(tenant_id=tenant_id, name="target-a", target_type=TargetType.AGENT)
    )
    fetched = service.get_target(
        GetAiTargetQuery(tenant_id=tenant_id, target_id=TargetId(UUID(dto.target_id)))
    )
    assert fetched == dto


def test_get_target_missing_returns_none() -> None:
    service = _service()
    fetched = service.get_target(
        GetAiTargetQuery(tenant_id=TenantId.generate(), target_id=TargetId.generate())
    )
    assert fetched is None


def test_list_targets_tenant_isolated() -> None:
    service = _service()
    tenant_a = TenantId.generate()
    tenant_b = TenantId.generate()
    service.register_target(
        RegisterAiTargetCommand(tenant_id=tenant_a, name="a1", target_type=TargetType.AGENT)
    )
    service.register_target(
        RegisterAiTargetCommand(tenant_id=tenant_b, name="b1", target_type=TargetType.MCP_SERVER)
    )
    result = service.list_targets(ListAiTargetsQuery(tenant_id=tenant_a))
    assert len(result) == 1
    assert result[0].name == "a1"
