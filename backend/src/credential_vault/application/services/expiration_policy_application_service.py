"""Expiration policy application service (command + read side)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid7

from credential_vault.application._validation import validate_str, validate_uuid
from credential_vault.application.dtos.policy_dtos import ExpirationPolicyDTO
from credential_vault.application.exceptions import ApplicationValidationError
from credential_vault.domain.aggregates.expiration_policy import ExpirationPolicy
from credential_vault.domain.exceptions.domain_exceptions import AccessDenied
from credential_vault.domain.ports.i_permission_port import IPermissionPort
from credential_vault.domain.value_objects.identifiers import (
    CredentialId,
    ExpirationPolicyId,
    PrincipalId,
    TenantId,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from credential_vault.application.commands.policy_commands import (
        CreateExpirationPolicyCommand,
        DeleteExpirationPolicyCommand,
        UpdateExpirationPolicyCommand,
    )
    from credential_vault.application.ports.i_event_publisher import IEventPublisher
    from credential_vault.application.ports.i_unit_of_work import IUnitOfWork
    from credential_vault.application.queries.policy_queries import (
        GetExpirationPolicyQuery,
        ListExpirationPoliciesQuery,
    )

logger = logging.getLogger(__name__)


class ExpirationPolicyApplicationService:
    """Orchestrates expiration policy CRUD with post-commit event publishing."""

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

    async def _require_manage_policy(
        self,
        principal_id: PrincipalId,
        resource_id: CredentialId,
        tenant_id: TenantId,
    ) -> None:
        allowed = await self._permission_port.has_permission(
            principal_id,
            resource_id,
            IPermissionPort.PERMISSION_MANAGE_POLICY,
            tenant_id,
        )
        if not allowed:
            raise AccessDenied(
                principal_id,
                IPermissionPort.PERMISSION_MANAGE_POLICY,
                resource_id,
            )

    def _validate_expiration_fields(self, *, ttl_days: int, warn_days_before: int) -> None:
        if not (1 <= ttl_days <= 3650):
            raise ApplicationValidationError("ttl_days", "must be 1-3650")
        if not (1 <= warn_days_before <= 90):
            raise ApplicationValidationError("warn_days_before", "must be 1-90")
        if warn_days_before >= ttl_days:
            raise ApplicationValidationError("warn_days_before", "must be less than ttl_days")

    async def create_expiration_policy(
        self, cmd: CreateExpirationPolicyCommand
    ) -> ExpirationPolicyDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.principal_id, "principal_id")
        validate_str(cmd.name, "name", 256)
        self._validate_expiration_fields(
            ttl_days=cmd.ttl_days, warn_days_before=cmd.warn_days_before
        )

        policy_uuid = uuid7()
        tenant_id = TenantId(cmd.tenant_id)
        principal = PrincipalId(cmd.principal_id)
        await self._require_manage_policy(principal, CredentialId(policy_uuid), tenant_id)

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            policy = ExpirationPolicy.create(
                ExpirationPolicyId(policy_uuid),
                tenant_id,
                cmd.name,
                cmd.ttl_days,
                cmd.warn_days_before,
                cmd.hard_expire,
                now,
            )
            await uow.expiration_policies.save(policy)
            await uow.commit()

        await self._publish([policy])
        return ExpirationPolicyDTO.from_aggregate(policy)

    async def update_expiration_policy(
        self, cmd: UpdateExpirationPolicyCommand
    ) -> ExpirationPolicyDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.policy_id, "policy_id")
        validate_uuid(cmd.principal_id, "principal_id")
        self._validate_expiration_fields(
            ttl_days=cmd.ttl_days, warn_days_before=cmd.warn_days_before
        )

        tenant_id = TenantId(cmd.tenant_id)
        policy_id = ExpirationPolicyId(cmd.policy_id)
        principal = PrincipalId(cmd.principal_id)
        await self._require_manage_policy(principal, CredentialId(cmd.policy_id), tenant_id)

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            policy = await uow.expiration_policies.get_by_id(policy_id, tenant_id)
            policy.update(
                tenant_id,
                cmd.ttl_days,
                cmd.warn_days_before,
                cmd.hard_expire,
                principal,
                now,
            )
            await uow.expiration_policies.save(policy)
            await uow.commit()

        await self._publish([policy])
        return ExpirationPolicyDTO.from_aggregate(policy)

    async def delete_expiration_policy(self, cmd: DeleteExpirationPolicyCommand) -> None:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.policy_id, "policy_id")
        validate_uuid(cmd.principal_id, "principal_id")

        tenant_id = TenantId(cmd.tenant_id)
        policy_id = ExpirationPolicyId(cmd.policy_id)
        principal = PrincipalId(cmd.principal_id)
        await self._require_manage_policy(principal, CredentialId(cmd.policy_id), tenant_id)

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            policy = await uow.expiration_policies.get_by_id(policy_id, tenant_id)
            policy.delete(tenant_id, principal, now)
            await uow.expiration_policies.delete(policy_id, tenant_id)
            await uow.commit()

        await self._publish([policy])

    async def get_expiration_policy(self, qry: GetExpirationPolicyQuery) -> ExpirationPolicyDTO:
        validate_uuid(qry.tenant_id, "tenant_id")
        validate_uuid(qry.policy_id, "policy_id")
        validate_uuid(qry.principal_id, "principal_id")

        tenant_id = TenantId(qry.tenant_id)
        policy_id = ExpirationPolicyId(qry.policy_id)
        await self._require_manage_policy(
            PrincipalId(qry.principal_id),
            CredentialId(qry.policy_id),
            tenant_id,
        )

        async with self._uow_factory() as uow:
            policy = await uow.expiration_policies.get_by_id(policy_id, tenant_id)
        return ExpirationPolicyDTO.from_aggregate(policy)

    async def list_expiration_policies(
        self, qry: ListExpirationPoliciesQuery
    ) -> list[ExpirationPolicyDTO]:
        validate_uuid(qry.tenant_id, "tenant_id")
        validate_uuid(qry.principal_id, "principal_id")

        tenant_id = TenantId(qry.tenant_id)
        resource_id = CredentialId(uuid7())
        await self._require_manage_policy(PrincipalId(qry.principal_id), resource_id, tenant_id)

        async with self._uow_factory() as uow:
            policies = await uow.expiration_policies.list_by_tenant(tenant_id)
        return [ExpirationPolicyDTO.from_aggregate(policy) for policy in policies]
