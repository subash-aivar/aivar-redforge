"""Tests for VaultBackendApplicationService."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from tests.credential_vault.application.conftest import make_vault_backend

from credential_vault.application.commands.backend_commands import (
    DeleteVaultBackendCommand,
    RegisterVaultBackendCommand,
)
from credential_vault.application.dtos.backend_dtos import VaultBackendDTO
from credential_vault.application.exceptions import ApplicationValidationError
from credential_vault.application.queries.backend_queries import (
    GetVaultBackendQuery,
    ListVaultBackendsQuery,
)
from credential_vault.application.services.vault_backend_application_service import (
    VaultBackendApplicationService,
)
from credential_vault.domain.events.backend_events import (
    VaultBackendDeleted,
    VaultBackendRegistered,
)
from credential_vault.domain.exceptions.domain_exceptions import AccessDenied
from credential_vault.domain.ports.i_permission_port import IPermissionPort
from credential_vault.domain.value_objects.audit_types import VaultBackendType
from credential_vault.domain.value_objects.identifiers import VaultBackendId
from redforge.shared.identifiers import EntityId


@pytest.fixture
def service(
    mock_uow_factory: MagicMock,
    mock_event_publisher: AsyncMock,
    mock_permission_port: AsyncMock,
) -> VaultBackendApplicationService:
    return VaultBackendApplicationService(
        uow_factory=mock_uow_factory,
        event_publisher=mock_event_publisher,
        permission_port=mock_permission_port,
    )


def _register_cmd(
    *,
    tenant_id=None,
    principal_id=None,
    name: str = "local-backend",
    backend_type: str = VaultBackendType.LOCAL_ENCRYPTED.value,
    config: dict[str, str] | None = None,
    is_default: bool = True,
) -> RegisterVaultBackendCommand:
    return RegisterVaultBackendCommand(
        tenant_id=tenant_id or uuid4(),
        principal_id=principal_id or EntityId.generate(),
        name=name,
        backend_type=backend_type,
        config=config if config is not None else {"path": "/secrets"},
        is_default=is_default,
    )


# --- register_vault_backend ---


async def test_register_vault_backend_success(
    service: VaultBackendApplicationService,
    mock_uow: AsyncMock,
    mock_event_publisher: AsyncMock,
) -> None:
    cmd = _register_cmd(
        name="primary",
        backend_type=VaultBackendType.HASHICORP_VAULT.value,
        config={"addr": "https://vault.local"},
        is_default=False,
    )

    dto = await service.register_vault_backend(cmd)

    assert isinstance(dto, VaultBackendDTO)
    assert dto.name == "primary"
    assert dto.backend_type == VaultBackendType.HASHICORP_VAULT.value
    assert dto.is_default is False
    assert dto.tenant_id == str(cmd.tenant_id)
    assert not hasattr(dto, "config")
    mock_uow.vault_backends.save.assert_awaited_once()
    mock_uow.commit.assert_awaited_once()
    events = mock_event_publisher.publish_batch.await_args.args[0]
    assert any(isinstance(e, VaultBackendRegistered) for e in events)
    mock_uow.audit_logs.append_entry.assert_not_called()


async def test_register_vault_backend_access_denied(
    service: VaultBackendApplicationService,
    mock_uow: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    mock_permission_port.has_permission.return_value = False

    with pytest.raises(AccessDenied) as exc_info:
        await service.register_vault_backend(_register_cmd())

    assert exc_info.value.required_permission == IPermissionPort.PERMISSION_ADMIN
    mock_uow.__aenter__.assert_not_awaited()
    mock_uow.vault_backends.save.assert_not_called()


async def test_register_vault_backend_validation_invalid_backend_type(
    service: VaultBackendApplicationService,
    mock_uow: AsyncMock,
) -> None:
    cmd = _register_cmd(backend_type="NOT_A_BACKEND")

    with pytest.raises(ApplicationValidationError) as exc_info:
        await service.register_vault_backend(cmd)

    assert exc_info.value.field == "backend_type"
    mock_uow.__aenter__.assert_not_awaited()


async def test_register_vault_backend_validation_config_too_many_keys(
    service: VaultBackendApplicationService,
    mock_uow: AsyncMock,
) -> None:
    cmd = _register_cmd(config={f"k{i}": "v" for i in range(101)})

    with pytest.raises(ApplicationValidationError) as exc_info:
        await service.register_vault_backend(cmd)

    assert exc_info.value.field == "config"
    assert "100" in exc_info.value.reason
    mock_uow.__aenter__.assert_not_awaited()


async def test_register_vault_backend_publish_failure_nonfatal(
    service: VaultBackendApplicationService,
    mock_uow: AsyncMock,
    mock_event_publisher: AsyncMock,
) -> None:
    mock_event_publisher.publish_batch.side_effect = RuntimeError("broker down")

    dto = await service.register_vault_backend(_register_cmd())

    assert isinstance(dto, VaultBackendDTO)
    assert not hasattr(dto, "config")
    mock_uow.commit.assert_awaited_once()


async def test_register_vault_backend_no_audit_append(
    service: VaultBackendApplicationService,
    mock_uow: AsyncMock,
) -> None:
    await service.register_vault_backend(_register_cmd())
    mock_uow.audit_logs.append_entry.assert_not_called()
    mock_uow.audit_logs.save.assert_not_called()


# --- delete_vault_backend ---


async def test_delete_vault_backend_success(
    service: VaultBackendApplicationService,
    mock_uow: AsyncMock,
    mock_event_publisher: AsyncMock,
) -> None:
    tenant_uuid = EntityId.generate()
    backend = make_vault_backend(tenant_id=tenant_uuid, name="to-delete")
    mock_uow.vault_backends.get_by_id.return_value = backend
    cmd = DeleteVaultBackendCommand(
        tenant_id=tenant_uuid,
        backend_id=backend.backend_id.value,
        principal_id=EntityId.generate(),
    )

    await service.delete_vault_backend(cmd)

    mock_uow.vault_backends.get_by_id.assert_awaited_once_with(
        VaultBackendId(backend.backend_id.value),
        tenant_uuid,
    )
    mock_uow.vault_backends.delete.assert_awaited_once_with(
        VaultBackendId(backend.backend_id.value),
        tenant_uuid,
    )
    mock_uow.commit.assert_awaited_once()
    events = mock_event_publisher.publish_batch.await_args.args[0]
    assert any(isinstance(e, VaultBackendDeleted) for e in events)
    mock_uow.audit_logs.append_entry.assert_not_called()


async def test_delete_vault_backend_access_denied(
    service: VaultBackendApplicationService,
    mock_uow: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    mock_permission_port.has_permission.return_value = False
    cmd = DeleteVaultBackendCommand(
        tenant_id=EntityId.generate(),
        backend_id=uuid4(),
        principal_id=EntityId.generate(),
    )

    with pytest.raises(AccessDenied) as exc_info:
        await service.delete_vault_backend(cmd)

    assert exc_info.value.required_permission == IPermissionPort.PERMISSION_ADMIN
    mock_uow.__aenter__.assert_not_awaited()
    mock_uow.vault_backends.delete.assert_not_called()


async def test_delete_vault_backend_validation_failure(
    service: VaultBackendApplicationService,
    mock_uow: AsyncMock,
) -> None:
    cmd = DeleteVaultBackendCommand(
        tenant_id=UUID(int=0),
        backend_id=uuid4(),
        principal_id=EntityId.generate(),
    )

    with pytest.raises(ApplicationValidationError) as exc_info:
        await service.delete_vault_backend(cmd)

    assert exc_info.value.field == "tenant_id"
    mock_uow.__aenter__.assert_not_awaited()


async def test_delete_vault_backend_publish_failure_nonfatal(
    service: VaultBackendApplicationService,
    mock_uow: AsyncMock,
    mock_event_publisher: AsyncMock,
) -> None:
    tenant_uuid = EntityId.generate()
    backend = make_vault_backend(tenant_id=tenant_uuid)
    mock_uow.vault_backends.get_by_id.return_value = backend
    mock_event_publisher.publish_batch.side_effect = RuntimeError("broker down")
    cmd = DeleteVaultBackendCommand(
        tenant_id=tenant_uuid,
        backend_id=backend.backend_id.value,
        principal_id=EntityId.generate(),
    )

    await service.delete_vault_backend(cmd)

    mock_uow.commit.assert_awaited_once()
    mock_uow.vault_backends.delete.assert_awaited_once()


# --- get_vault_backend ---


async def test_get_vault_backend_success(
    service: VaultBackendApplicationService,
    mock_uow: AsyncMock,
) -> None:
    tenant_uuid = EntityId.generate()
    backend = make_vault_backend(tenant_id=tenant_uuid, name="lookup")
    mock_uow.vault_backends.get_by_id.return_value = backend
    qry = GetVaultBackendQuery(
        tenant_id=tenant_uuid,
        backend_id=backend.backend_id.value,
        principal_id=EntityId.generate(),
    )

    dto = await service.get_vault_backend(qry)

    assert dto.name == "lookup"
    assert dto.backend_id == str(backend.backend_id)
    assert not hasattr(dto, "config")
    mock_uow.vault_backends.get_by_id.assert_awaited_once()
    mock_uow.commit.assert_not_called()


async def test_get_vault_backend_access_denied(
    service: VaultBackendApplicationService,
    mock_uow: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    mock_permission_port.has_permission.return_value = False
    qry = GetVaultBackendQuery(
        tenant_id=EntityId.generate(),
        backend_id=uuid4(),
        principal_id=EntityId.generate(),
    )

    with pytest.raises(AccessDenied) as exc_info:
        await service.get_vault_backend(qry)

    assert exc_info.value.required_permission == IPermissionPort.PERMISSION_ADMIN
    mock_uow.__aenter__.assert_not_awaited()


# --- list_vault_backends ---


async def test_list_vault_backends_success(
    service: VaultBackendApplicationService,
    mock_uow: AsyncMock,
) -> None:
    tenant_uuid = EntityId.generate()
    backends = [
        make_vault_backend(tenant_id=tenant_uuid, name="a"),
        make_vault_backend(tenant_id=tenant_uuid, name="b"),
    ]
    mock_uow.vault_backends.list_by_tenant.return_value = backends
    qry = ListVaultBackendsQuery(tenant_id=tenant_uuid, principal_id=EntityId.generate())

    result = await service.list_vault_backends(qry)

    assert len(result) == 2
    assert {dto.name for dto in result} == {"a", "b"}
    assert all(not hasattr(dto, "config") for dto in result)
    mock_uow.vault_backends.list_by_tenant.assert_awaited_once_with(tenant_uuid)
    mock_uow.commit.assert_not_called()


async def test_list_vault_backends_access_denied(
    service: VaultBackendApplicationService,
    mock_uow: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    mock_permission_port.has_permission.return_value = False
    qry = ListVaultBackendsQuery(tenant_id=EntityId.generate(), principal_id=EntityId.generate())

    with pytest.raises(AccessDenied) as exc_info:
        await service.list_vault_backends(qry)

    assert exc_info.value.required_permission == IPermissionPort.PERMISSION_ADMIN
    mock_uow.__aenter__.assert_not_awaited()
    mock_uow.vault_backends.list_by_tenant.assert_not_called()
