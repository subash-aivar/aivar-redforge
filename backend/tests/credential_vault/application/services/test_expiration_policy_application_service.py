"""Tests for ExpirationPolicyApplicationService."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from tests.credential_vault.application.conftest import make_expiration_policy

from credential_vault.application.commands.policy_commands import (
    CreateExpirationPolicyCommand,
    DeleteExpirationPolicyCommand,
    UpdateExpirationPolicyCommand,
)
from credential_vault.application.dtos.policy_dtos import ExpirationPolicyDTO
from credential_vault.application.exceptions import ApplicationValidationError
from credential_vault.application.queries.policy_queries import (
    GetExpirationPolicyQuery,
    ListExpirationPoliciesQuery,
)
from credential_vault.application.services.expiration_policy_application_service import (
    ExpirationPolicyApplicationService,
)
from credential_vault.domain.events.policy_events import (
    ExpirationPolicyCreated,
    ExpirationPolicyDeleted,
    ExpirationPolicyUpdated,
)
from credential_vault.domain.exceptions.domain_exceptions import AccessDenied
from credential_vault.domain.ports.i_permission_port import IPermissionPort
from credential_vault.domain.value_objects.identifiers import (
    ExpirationPolicyId,
    TenantId,
)


@pytest.fixture
def service(
    mock_uow_factory: MagicMock,
    mock_event_publisher: AsyncMock,
    mock_permission_port: AsyncMock,
) -> ExpirationPolicyApplicationService:
    return ExpirationPolicyApplicationService(
        uow_factory=mock_uow_factory,
        event_publisher=mock_event_publisher,
        permission_port=mock_permission_port,
    )


def _create_cmd(
    *,
    tenant_id=None,
    principal_id=None,
    name: str = "exp-policy",
    ttl_days: int = 90,
    warn_days_before: int = 14,
    hard_expire: bool = True,
) -> CreateExpirationPolicyCommand:
    return CreateExpirationPolicyCommand(
        tenant_id=tenant_id or uuid4(),
        principal_id=principal_id or uuid4(),
        name=name,
        ttl_days=ttl_days,
        warn_days_before=warn_days_before,
        hard_expire=hard_expire,
    )


# --- create_expiration_policy ---


async def test_create_expiration_policy_success(
    service: ExpirationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_event_publisher: AsyncMock,
) -> None:
    cmd = _create_cmd(name="90d-expire", ttl_days=90, warn_days_before=14, hard_expire=False)

    dto = await service.create_expiration_policy(cmd)

    assert isinstance(dto, ExpirationPolicyDTO)
    assert dto.name == "90d-expire"
    assert dto.tenant_id == str(cmd.tenant_id)
    assert dto.ttl_days == 90
    assert dto.warn_days_before == 14
    assert dto.hard_expire is False
    mock_uow.expiration_policies.save.assert_awaited_once()
    mock_uow.commit.assert_awaited_once()
    events = mock_event_publisher.publish_batch.await_args.args[0]
    assert any(isinstance(e, ExpirationPolicyCreated) for e in events)
    mock_uow.audit_logs.append_entry.assert_not_called()


async def test_create_expiration_policy_access_denied(
    service: ExpirationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    mock_permission_port.has_permission.return_value = False

    with pytest.raises(AccessDenied) as exc_info:
        await service.create_expiration_policy(_create_cmd())

    assert exc_info.value.required_permission == IPermissionPort.PERMISSION_MANAGE_POLICY
    mock_uow.__aenter__.assert_not_awaited()
    mock_uow.expiration_policies.save.assert_not_called()


async def test_create_expiration_policy_validation_failure_warn_ge_ttl(
    service: ExpirationPolicyApplicationService,
    mock_uow: AsyncMock,
) -> None:
    cmd = _create_cmd(ttl_days=10, warn_days_before=10)

    with pytest.raises(ApplicationValidationError) as exc_info:
        await service.create_expiration_policy(cmd)

    assert exc_info.value.field == "warn_days_before"
    assert "less than ttl_days" in exc_info.value.reason
    mock_uow.__aenter__.assert_not_awaited()


async def test_create_expiration_policy_validation_failure_ttl_range(
    service: ExpirationPolicyApplicationService,
    mock_uow: AsyncMock,
) -> None:
    with pytest.raises(ApplicationValidationError) as exc_info:
        await service.create_expiration_policy(_create_cmd(ttl_days=0, warn_days_before=1))

    assert exc_info.value.field == "ttl_days"
    mock_uow.__aenter__.assert_not_awaited()


async def test_create_expiration_policy_publish_failure_nonfatal(
    service: ExpirationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_event_publisher: AsyncMock,
) -> None:
    mock_event_publisher.publish_batch.side_effect = RuntimeError("broker down")

    dto = await service.create_expiration_policy(_create_cmd())

    assert isinstance(dto, ExpirationPolicyDTO)
    mock_uow.commit.assert_awaited_once()
    mock_event_publisher.publish_batch.assert_awaited_once()


async def test_create_expiration_policy_no_audit_append(
    service: ExpirationPolicyApplicationService,
    mock_uow: AsyncMock,
) -> None:
    await service.create_expiration_policy(_create_cmd())
    mock_uow.audit_logs.append_entry.assert_not_called()
    mock_uow.audit_logs.save.assert_not_called()


# --- update_expiration_policy ---


async def test_update_expiration_policy_success(
    service: ExpirationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_event_publisher: AsyncMock,
) -> None:
    tenant_uuid = uuid4()
    policy = make_expiration_policy(tenant_id=TenantId(tenant_uuid), name="existing")
    mock_uow.expiration_policies.get_by_id.return_value = policy
    cmd = UpdateExpirationPolicyCommand(
        tenant_id=tenant_uuid,
        policy_id=policy.policy_id.value,
        principal_id=uuid4(),
        ttl_days=180,
        warn_days_before=30,
        hard_expire=False,
    )

    dto = await service.update_expiration_policy(cmd)

    assert dto.ttl_days == 180
    assert dto.warn_days_before == 30
    assert dto.hard_expire is False
    mock_uow.expiration_policies.save.assert_awaited_once_with(policy)
    mock_uow.commit.assert_awaited_once()
    events = mock_event_publisher.publish_batch.await_args.args[0]
    assert any(isinstance(e, ExpirationPolicyUpdated) for e in events)
    mock_uow.audit_logs.append_entry.assert_not_called()


async def test_update_expiration_policy_access_denied(
    service: ExpirationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    mock_permission_port.has_permission.return_value = False
    cmd = UpdateExpirationPolicyCommand(
        tenant_id=uuid4(),
        policy_id=uuid4(),
        principal_id=uuid4(),
        ttl_days=90,
        warn_days_before=14,
        hard_expire=True,
    )

    with pytest.raises(AccessDenied):
        await service.update_expiration_policy(cmd)

    mock_uow.__aenter__.assert_not_awaited()


async def test_update_expiration_policy_validation_failure_warn_ge_ttl(
    service: ExpirationPolicyApplicationService,
    mock_uow: AsyncMock,
) -> None:
    cmd = UpdateExpirationPolicyCommand(
        tenant_id=uuid4(),
        policy_id=uuid4(),
        principal_id=uuid4(),
        ttl_days=7,
        warn_days_before=14,
        hard_expire=True,
    )

    with pytest.raises(ApplicationValidationError) as exc_info:
        await service.update_expiration_policy(cmd)

    assert exc_info.value.field == "warn_days_before"
    mock_uow.__aenter__.assert_not_awaited()


async def test_update_expiration_policy_publish_failure_nonfatal(
    service: ExpirationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_event_publisher: AsyncMock,
) -> None:
    tenant_uuid = uuid4()
    policy = make_expiration_policy(tenant_id=TenantId(tenant_uuid))
    mock_uow.expiration_policies.get_by_id.return_value = policy
    mock_event_publisher.publish_batch.side_effect = RuntimeError("broker down")
    cmd = UpdateExpirationPolicyCommand(
        tenant_id=tenant_uuid,
        policy_id=policy.policy_id.value,
        principal_id=uuid4(),
        ttl_days=120,
        warn_days_before=10,
        hard_expire=True,
    )

    dto = await service.update_expiration_policy(cmd)

    assert dto.ttl_days == 120
    mock_uow.commit.assert_awaited_once()


# --- delete_expiration_policy ---


async def test_delete_expiration_policy_success(
    service: ExpirationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_event_publisher: AsyncMock,
) -> None:
    tenant_uuid = uuid4()
    policy = make_expiration_policy(tenant_id=TenantId(tenant_uuid))
    mock_uow.expiration_policies.get_by_id.return_value = policy
    cmd = DeleteExpirationPolicyCommand(
        tenant_id=tenant_uuid,
        policy_id=policy.policy_id.value,
        principal_id=uuid4(),
    )

    await service.delete_expiration_policy(cmd)

    mock_uow.expiration_policies.get_by_id.assert_awaited_once_with(
        ExpirationPolicyId(policy.policy_id.value),
        TenantId(tenant_uuid),
    )
    mock_uow.expiration_policies.delete.assert_awaited_once_with(
        ExpirationPolicyId(policy.policy_id.value),
        TenantId(tenant_uuid),
    )
    mock_uow.commit.assert_awaited_once()
    events = mock_event_publisher.publish_batch.await_args.args[0]
    assert any(isinstance(e, ExpirationPolicyDeleted) for e in events)
    mock_uow.audit_logs.append_entry.assert_not_called()


async def test_delete_expiration_policy_access_denied(
    service: ExpirationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    mock_permission_port.has_permission.return_value = False
    cmd = DeleteExpirationPolicyCommand(
        tenant_id=uuid4(),
        policy_id=uuid4(),
        principal_id=uuid4(),
    )

    with pytest.raises(AccessDenied):
        await service.delete_expiration_policy(cmd)

    mock_uow.__aenter__.assert_not_awaited()
    mock_uow.expiration_policies.delete.assert_not_called()


async def test_delete_expiration_policy_validation_failure(
    service: ExpirationPolicyApplicationService,
    mock_uow: AsyncMock,
) -> None:
    cmd = DeleteExpirationPolicyCommand(
        tenant_id=UUID(int=0),
        policy_id=uuid4(),
        principal_id=uuid4(),
    )

    with pytest.raises(ApplicationValidationError) as exc_info:
        await service.delete_expiration_policy(cmd)

    assert exc_info.value.field == "tenant_id"
    mock_uow.__aenter__.assert_not_awaited()


async def test_delete_expiration_policy_publish_failure_nonfatal(
    service: ExpirationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_event_publisher: AsyncMock,
) -> None:
    tenant_uuid = uuid4()
    policy = make_expiration_policy(tenant_id=TenantId(tenant_uuid))
    mock_uow.expiration_policies.get_by_id.return_value = policy
    mock_event_publisher.publish_batch.side_effect = RuntimeError("broker down")
    cmd = DeleteExpirationPolicyCommand(
        tenant_id=tenant_uuid,
        policy_id=policy.policy_id.value,
        principal_id=uuid4(),
    )

    await service.delete_expiration_policy(cmd)

    mock_uow.commit.assert_awaited_once()
    mock_uow.expiration_policies.delete.assert_awaited_once()


# --- get_expiration_policy ---


async def test_get_expiration_policy_success(
    service: ExpirationPolicyApplicationService,
    mock_uow: AsyncMock,
) -> None:
    tenant_uuid = uuid4()
    policy = make_expiration_policy(tenant_id=TenantId(tenant_uuid), name="lookup")
    mock_uow.expiration_policies.get_by_id.return_value = policy
    qry = GetExpirationPolicyQuery(
        tenant_id=tenant_uuid,
        policy_id=policy.policy_id.value,
        principal_id=uuid4(),
    )

    dto = await service.get_expiration_policy(qry)

    assert dto.name == "lookup"
    assert dto.policy_id == str(policy.policy_id)
    mock_uow.expiration_policies.get_by_id.assert_awaited_once()
    mock_uow.commit.assert_not_called()


async def test_get_expiration_policy_access_denied(
    service: ExpirationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    mock_permission_port.has_permission.return_value = False
    qry = GetExpirationPolicyQuery(
        tenant_id=uuid4(),
        policy_id=uuid4(),
        principal_id=uuid4(),
    )

    with pytest.raises(AccessDenied):
        await service.get_expiration_policy(qry)

    mock_uow.__aenter__.assert_not_awaited()


# --- list_expiration_policies ---


async def test_list_expiration_policies_success(
    service: ExpirationPolicyApplicationService,
    mock_uow: AsyncMock,
) -> None:
    tenant_uuid = uuid4()
    policies = [
        make_expiration_policy(tenant_id=TenantId(tenant_uuid), name="a"),
        make_expiration_policy(tenant_id=TenantId(tenant_uuid), name="b"),
    ]
    mock_uow.expiration_policies.list_by_tenant.return_value = policies
    qry = ListExpirationPoliciesQuery(tenant_id=tenant_uuid, principal_id=uuid4())

    result = await service.list_expiration_policies(qry)

    assert len(result) == 2
    assert {dto.name for dto in result} == {"a", "b"}
    mock_uow.expiration_policies.list_by_tenant.assert_awaited_once_with(TenantId(tenant_uuid))
    mock_uow.commit.assert_not_called()


async def test_list_expiration_policies_access_denied(
    service: ExpirationPolicyApplicationService,
    mock_uow: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    mock_permission_port.has_permission.return_value = False
    qry = ListExpirationPoliciesQuery(tenant_id=uuid4(), principal_id=uuid4())

    with pytest.raises(AccessDenied):
        await service.list_expiration_policies(qry)

    mock_uow.__aenter__.assert_not_awaited()
    mock_uow.expiration_policies.list_by_tenant.assert_not_called()
