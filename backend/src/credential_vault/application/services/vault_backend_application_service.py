"""Vault backend application service (command + read side)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid7

from credential_vault.application._validation import validate_str, validate_uuid
from credential_vault.application.dtos.backend_dtos import VaultBackendDTO
from credential_vault.application.exceptions import ApplicationValidationError
from credential_vault.domain.aggregates.vault_backend import VaultBackend
from credential_vault.domain.exceptions.domain_exceptions import AccessDenied
from credential_vault.domain.ports.i_permission_port import IPermissionPort
from credential_vault.domain.value_objects.audit_types import VaultBackendType
from credential_vault.domain.value_objects.identifiers import (
    CredentialId,
    PrincipalId,
    TenantId,
    VaultBackendId,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from credential_vault.application.commands.backend_commands import (
        DeleteVaultBackendCommand,
        RegisterVaultBackendCommand,
    )
    from credential_vault.application.ports.i_event_publisher import IEventPublisher
    from credential_vault.application.ports.i_unit_of_work import IUnitOfWork
    from credential_vault.application.queries.backend_queries import (
        GetVaultBackendQuery,
        ListVaultBackendsQuery,
    )

logger = logging.getLogger(__name__)


class VaultBackendApplicationService:
    """Orchestrates vault backend registration/deletion with post-commit events."""

    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        permission_port: IPermissionPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher
        self._permission_port = permission_port

    async def _publish(self, aggregates: list[Any]) -> None:
        events: list[Any] = []
        for aggregate in aggregates:
            events.extend(aggregate.pop_events())
        try:
            await self._event_publisher.publish_batch(events)
        except Exception as exc:
            logger.warning("Event publication failed: %s", exc)

    async def _require_admin(
        self,
        principal_id: PrincipalId,
        resource_id: CredentialId,
        tenant_id: TenantId,
    ) -> None:
        allowed = await self._permission_port.has_permission(
            principal_id,
            resource_id,
            IPermissionPort.PERMISSION_ADMIN,
            tenant_id,
        )
        if not allowed:
            raise AccessDenied(
                principal_id,
                IPermissionPort.PERMISSION_ADMIN,
                resource_id,
            )

    def _validate_config(self, config: dict[str, str]) -> None:
        if len(config) > 100:
            raise ApplicationValidationError("config", "max 100 keys")
        for key, value in config.items():
            if len(value) > 2048:
                raise ApplicationValidationError(
                    "config", f"value for key '{key}' exceeds 2048 chars"
                )

    async def register_vault_backend(self, cmd: RegisterVaultBackendCommand) -> VaultBackendDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.principal_id, "principal_id")
        validate_str(cmd.name, "name", 256)
        try:
            backend_type = VaultBackendType(cmd.backend_type)
        except ValueError as exc:
            raise ApplicationValidationError(
                "backend_type", "must be a valid VaultBackendType"
            ) from exc
        self._validate_config(cmd.config)

        backend_uuid = uuid7()
        tenant_id = TenantId(cmd.tenant_id)
        principal = PrincipalId(cmd.principal_id)
        await self._require_admin(principal, CredentialId(backend_uuid), tenant_id)

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            backend = VaultBackend.create(
                VaultBackendId(backend_uuid),
                tenant_id,
                cmd.name,
                backend_type,
                cmd.config,
                cmd.is_default,
                now,
            )
            await uow.vault_backends.save(backend)
            await uow.commit()

        await self._publish([backend])
        return VaultBackendDTO.from_aggregate(backend)

    async def delete_vault_backend(self, cmd: DeleteVaultBackendCommand) -> None:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.backend_id, "backend_id")
        validate_uuid(cmd.principal_id, "principal_id")

        tenant_id = TenantId(cmd.tenant_id)
        backend_id = VaultBackendId(cmd.backend_id)
        principal = PrincipalId(cmd.principal_id)
        await self._require_admin(principal, CredentialId(cmd.backend_id), tenant_id)

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            backend = await uow.vault_backends.get_by_id(backend_id, tenant_id)
            backend.delete(tenant_id, principal, now)
            await uow.vault_backends.delete(backend_id, tenant_id)
            await uow.commit()

        await self._publish([backend])

    async def get_vault_backend(self, qry: GetVaultBackendQuery) -> VaultBackendDTO:
        validate_uuid(qry.tenant_id, "tenant_id")
        validate_uuid(qry.backend_id, "backend_id")
        validate_uuid(qry.principal_id, "principal_id")

        tenant_id = TenantId(qry.tenant_id)
        backend_id = VaultBackendId(qry.backend_id)
        await self._require_admin(
            PrincipalId(qry.principal_id),
            CredentialId(qry.backend_id),
            tenant_id,
        )

        async with self._uow_factory() as uow:
            backend = await uow.vault_backends.get_by_id(backend_id, tenant_id)
        return VaultBackendDTO.from_aggregate(backend)

    async def list_vault_backends(self, qry: ListVaultBackendsQuery) -> list[VaultBackendDTO]:
        validate_uuid(qry.tenant_id, "tenant_id")
        validate_uuid(qry.principal_id, "principal_id")

        tenant_id = TenantId(qry.tenant_id)
        resource_id = CredentialId(uuid7())
        await self._require_admin(PrincipalId(qry.principal_id), resource_id, tenant_id)

        async with self._uow_factory() as uow:
            backends = await uow.vault_backends.list_by_tenant(tenant_id)
        return [VaultBackendDTO.from_aggregate(backend) for backend in backends]
