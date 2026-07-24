"""Tests for RotationPolicyApplicationService."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from tests.credential_vault.application.conftest import make_rotation_policy

from credential_vault.application.commands.policy_commands import (
    CreateRotationPolicyCommand,
    DeleteRotationPolicyCommand,
    UpdateRotationPolicyCommand,
)
from credential_vault.application.dtos.policy_dtos import RotationPolicyDTO
from credential_vault.application.exceptions import ApplicationValidationError
from credential_vault.application.queries.policy_queries import (
    GetRotationPolicyQuery,
    ListRotationPoliciesQuery,
)
from credential_vault.application.services.rotation_policy_application_service import (
    RotationPolicyApplicationService,
)
from credential_vault.domain.events.policy_events import (
    RotationPolicyCreated,
    RotationPolicyDeleted,
    RotationPolicyUpdated,
)
from credential_vault.domain.exceptions.domain_exceptions import AccessDenied
from credential_vault.domain.ports.i_permission_port import IPermissionPort
from credential_vault.domain.value_objects.identifiers import (
    RotationPolicyId,
)
from redforge.shared.identifiers import EntityId


@pytest.fixture
def service(
    mock_uow_factory: MagicMock,
    mock_event_publisher: AsyncMock,
    mock_permission_port: AsyncMock,
) -> RotationPolicyApplicationService:
    return RotationPolicyApplicationService(
        uow_factory=mock_uow_factory,
        event_publisher=mock_event_publisher,
        permission_port=mock_permission_port,
    )


def _create_cmd(
    *,
    tenant_id=None,
    principal_id=None,
    name: str = "rot-policy",
    interval_days: int | None = 30,
    max_versions_kept: int = 5,
    notify_days_before: int = 7,
    auto_rotate: bool = True,
) -> CreateRotationPolicyCommand:
    return CreateRotationPolicyCommand(
        tenant_id=tenant_id or uuid4(),
        principal_id=principal_id or EntityId.generate(),
        name=name,
        interval_days=interval_days,
        max_versions_kept=max_versions_kept,
        notify_days_before=notify_days_before,
        auto_rotate=auto_rotate,
    )


# --- create_rotation_policy ---


async def test_create_rotation_policy_success(
    service: RotationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_event_publisher: AsyncMock,
) -> None:
    cmd = _create_cmd(name="nightly-rotate", interval_days=14, max_versions_kept=3)

    dto = await service.create_rotation_policy(cmd)

    assert isinstance(dto, RotationPolicyDTO)
    assert dto.name == "nightly-rotate"
    assert dto.tenant_id == str(cmd.tenant_id)
    assert dto.interval_days == 14
    assert dto.max_versions_kept == 3
    assert dto.notify_days_before == 7
    assert dto.auto_rotate is True
    mock_uow.rotation_policies.save.assert_awaited_once()
    mock_uow.commit.assert_awaited_once()
    mock_event_publisher.publish_batch.assert_awaited_once()
    events = mock_event_publisher.publish_batch.await_args.args[0]
    assert any(isinstance(e, RotationPolicyCreated) for e in events)
    mock_uow.audit_logs.append_entry.assert_not_called()


async def test_create_rotation_policy_access_denied(
    service: RotationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    mock_permission_port.has_permission.return_value = False
    cmd = _create_cmd()

    with pytest.raises(AccessDenied) as exc_info:
        await service.create_rotation_policy(cmd)

    assert exc_info.value.required_permission == IPermissionPort.PERMISSION_MANAGE_POLICY
    mock_uow.__aenter__.assert_not_awaited()
    mock_uow.rotation_policies.save.assert_not_called()
    mock_uow.commit.assert_not_called()


async def test_create_rotation_policy_validation_failure(
    service: RotationPolicyApplicationService,
    mock_uow: AsyncMock,
) -> None:
    cmd = _create_cmd(interval_days=0)

    with pytest.raises(ApplicationValidationError) as exc_info:
        await service.create_rotation_policy(cmd)

    assert exc_info.value.field == "interval_days"
    mock_uow.__aenter__.assert_not_awaited()


async def test_create_rotation_policy_publish_failure_nonfatal(
    service: RotationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_event_publisher: AsyncMock,
) -> None:
    mock_event_publisher.publish_batch.side_effect = RuntimeError("broker down")
    cmd = _create_cmd()

    dto = await service.create_rotation_policy(cmd)

    assert isinstance(dto, RotationPolicyDTO)
    mock_uow.commit.assert_awaited_once()
    mock_event_publisher.publish_batch.assert_awaited_once()


async def test_create_rotation_policy_no_audit_append(
    service: RotationPolicyApplicationService,
    mock_uow: AsyncMock,
) -> None:
    await service.create_rotation_policy(_create_cmd())
    mock_uow.audit_logs.append_entry.assert_not_called()
    mock_uow.audit_logs.save.assert_not_called()


# --- update_rotation_policy ---


async def test_update_rotation_policy_success(
    service: RotationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_event_publisher: AsyncMock,
) -> None:
    tenant_uuid = EntityId.generate()
    policy = make_rotation_policy(tenant_id=tenant_uuid, name="existing")
    mock_uow.rotation_policies.get_by_id.return_value = policy
    cmd = UpdateRotationPolicyCommand(
        tenant_id=tenant_uuid,
        policy_id=policy.policy_id.value,
        principal_id=EntityId.generate(),
        interval_days=60,
        max_versions_kept=10,
        notify_days_before=3,
        auto_rotate=False,
    )

    dto = await service.update_rotation_policy(cmd)

    assert dto.interval_days == 60
    assert dto.max_versions_kept == 10
    assert dto.notify_days_before == 3
    assert dto.auto_rotate is False
    mock_uow.rotation_policies.get_by_id.assert_awaited_once()
    mock_uow.rotation_policies.save.assert_awaited_once_with(policy)
    mock_uow.commit.assert_awaited_once()
    events = mock_event_publisher.publish_batch.await_args.args[0]
    assert any(isinstance(e, RotationPolicyUpdated) for e in events)
    mock_uow.audit_logs.append_entry.assert_not_called()


async def test_update_rotation_policy_access_denied(
    service: RotationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    mock_permission_port.has_permission.return_value = False
    policy_id = uuid4()
    cmd = UpdateRotationPolicyCommand(
        tenant_id=EntityId.generate(),
        policy_id=policy_id,
        principal_id=EntityId.generate(),
        interval_days=30,
        max_versions_kept=5,
        notify_days_before=7,
        auto_rotate=True,
    )

    with pytest.raises(AccessDenied):
        await service.update_rotation_policy(cmd)

    mock_uow.__aenter__.assert_not_awaited()
    mock_uow.rotation_policies.save.assert_not_called()


async def test_update_rotation_policy_validation_failure(
    service: RotationPolicyApplicationService,
    mock_uow: AsyncMock,
) -> None:
    cmd = UpdateRotationPolicyCommand(
        tenant_id=EntityId.generate(),
        policy_id=uuid4(),
        principal_id=EntityId.generate(),
        interval_days=30,
        max_versions_kept=0,
        notify_days_before=7,
        auto_rotate=True,
    )

    with pytest.raises(ApplicationValidationError) as exc_info:
        await service.update_rotation_policy(cmd)

    assert exc_info.value.field == "max_versions_kept"
    mock_uow.__aenter__.assert_not_awaited()


async def test_update_rotation_policy_publish_failure_nonfatal(
    service: RotationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_event_publisher: AsyncMock,
) -> None:
    tenant_uuid = EntityId.generate()
    policy = make_rotation_policy(tenant_id=tenant_uuid)
    mock_uow.rotation_policies.get_by_id.return_value = policy
    mock_event_publisher.publish_batch.side_effect = RuntimeError("broker down")
    cmd = UpdateRotationPolicyCommand(
        tenant_id=tenant_uuid,
        policy_id=policy.policy_id.value,
        principal_id=EntityId.generate(),
        interval_days=45,
        max_versions_kept=5,
        notify_days_before=7,
        auto_rotate=True,
    )

    dto = await service.update_rotation_policy(cmd)

    assert dto.interval_days == 45
    mock_uow.commit.assert_awaited_once()


# --- delete_rotation_policy ---


async def test_delete_rotation_policy_success(
    service: RotationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_event_publisher: AsyncMock,
) -> None:
    tenant_uuid = EntityId.generate()
    policy = make_rotation_policy(tenant_id=tenant_uuid)
    mock_uow.rotation_policies.get_by_id.return_value = policy
    cmd = DeleteRotationPolicyCommand(
        tenant_id=tenant_uuid,
        policy_id=policy.policy_id.value,
        principal_id=EntityId.generate(),
    )

    await service.delete_rotation_policy(cmd)

    mock_uow.rotation_policies.get_by_id.assert_awaited_once_with(
        RotationPolicyId(policy.policy_id.value),
        tenant_uuid,
    )
    mock_uow.rotation_policies.delete.assert_awaited_once_with(
        RotationPolicyId(policy.policy_id.value),
        tenant_uuid,
    )
    mock_uow.commit.assert_awaited_once()
    events = mock_event_publisher.publish_batch.await_args.args[0]
    assert any(isinstance(e, RotationPolicyDeleted) for e in events)
    mock_uow.audit_logs.append_entry.assert_not_called()


async def test_delete_rotation_policy_access_denied(
    service: RotationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    mock_permission_port.has_permission.return_value = False
    cmd = DeleteRotationPolicyCommand(
        tenant_id=EntityId.generate(),
        policy_id=uuid4(),
        principal_id=EntityId.generate(),
    )

    with pytest.raises(AccessDenied):
        await service.delete_rotation_policy(cmd)

    mock_uow.__aenter__.assert_not_awaited()
    mock_uow.rotation_policies.delete.assert_not_called()


async def test_delete_rotation_policy_validation_failure(
    service: RotationPolicyApplicationService,
    mock_uow: AsyncMock,
) -> None:
    from uuid import UUID

    cmd = DeleteRotationPolicyCommand(
        tenant_id=UUID(int=0),
        policy_id=uuid4(),
        principal_id=EntityId.generate(),
    )

    with pytest.raises(ApplicationValidationError) as exc_info:
        await service.delete_rotation_policy(cmd)

    assert exc_info.value.field == "tenant_id"
    mock_uow.__aenter__.assert_not_awaited()


async def test_delete_rotation_policy_publish_failure_nonfatal(
    service: RotationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_event_publisher: AsyncMock,
) -> None:
    tenant_uuid = EntityId.generate()
    policy = make_rotation_policy(tenant_id=tenant_uuid)
    mock_uow.rotation_policies.get_by_id.return_value = policy
    mock_event_publisher.publish_batch.side_effect = RuntimeError("broker down")
    cmd = DeleteRotationPolicyCommand(
        tenant_id=tenant_uuid,
        policy_id=policy.policy_id.value,
        principal_id=EntityId.generate(),
    )

    await service.delete_rotation_policy(cmd)

    mock_uow.commit.assert_awaited_once()
    mock_uow.rotation_policies.delete.assert_awaited_once()


# --- get_rotation_policy ---


async def test_get_rotation_policy_success(
    service: RotationPolicyApplicationService,
    mock_uow: AsyncMock,
) -> None:
    tenant_uuid = EntityId.generate()
    policy = make_rotation_policy(tenant_id=tenant_uuid, name="lookup")
    mock_uow.rotation_policies.get_by_id.return_value = policy
    qry = GetRotationPolicyQuery(
        tenant_id=tenant_uuid,
        policy_id=policy.policy_id.value,
        principal_id=EntityId.generate(),
    )

    dto = await service.get_rotation_policy(qry)

    assert dto.name == "lookup"
    assert dto.policy_id == str(policy.policy_id)
    mock_uow.rotation_policies.get_by_id.assert_awaited_once()
    mock_uow.commit.assert_not_called()
    mock_uow.audit_logs.append_entry.assert_not_called()


async def test_get_rotation_policy_access_denied(
    service: RotationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    mock_permission_port.has_permission.return_value = False
    qry = GetRotationPolicyQuery(
        tenant_id=EntityId.generate(),
        policy_id=uuid4(),
        principal_id=EntityId.generate(),
    )

    with pytest.raises(AccessDenied):
        await service.get_rotation_policy(qry)

    mock_uow.__aenter__.assert_not_awaited()


# --- list_rotation_policies ---


async def test_list_rotation_policies_success(
    service: RotationPolicyApplicationService,
    mock_uow: AsyncMock,
) -> None:
    tenant_uuid = EntityId.generate()
    policies = [
        make_rotation_policy(tenant_id=tenant_uuid, name="a"),
        make_rotation_policy(tenant_id=tenant_uuid, name="b"),
    ]
    mock_uow.rotation_policies.list_by_tenant.return_value = policies
    qry = ListRotationPoliciesQuery(tenant_id=tenant_uuid, principal_id=EntityId.generate())

    result = await service.list_rotation_policies(qry)

    assert len(result) == 2
    assert {dto.name for dto in result} == {"a", "b"}
    mock_uow.rotation_policies.list_by_tenant.assert_awaited_once_with(tenant_uuid)
    mock_uow.commit.assert_not_called()


async def test_list_rotation_policies_access_denied(
    service: RotationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    mock_permission_port.has_permission.return_value = False
    qry = ListRotationPoliciesQuery(tenant_id=EntityId.generate(), principal_id=EntityId.generate())

    with pytest.raises(AccessDenied):
        await service.list_rotation_policies(qry)

    mock_uow.__aenter__.assert_not_awaited()
    mock_uow.rotation_policies.list_by_tenant.assert_not_called()
