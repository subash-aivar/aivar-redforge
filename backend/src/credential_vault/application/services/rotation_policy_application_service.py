"""Rotation policy application service (command + read side)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid7

from credential_vault.application._validation import validate_str, validate_uuid
from credential_vault.application.dtos.policy_dtos import RotationPolicyDTO
from credential_vault.application.exceptions import ApplicationValidationError
from credential_vault.domain.aggregates.rotation_policy import RotationPolicy
from credential_vault.domain.exceptions.domain_exceptions import AccessDenied
from credential_vault.domain.ports.i_permission_port import IPermissionPort
from credential_vault.domain.value_objects.identifiers import (
    CredentialId,
    PrincipalId,
    RotationPolicyId,
    TenantId,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from credential_vault.application.commands.policy_commands import (
        CreateRotationPolicyCommand,
        DeleteRotationPolicyCommand,
        UpdateRotationPolicyCommand,
    )
    from credential_vault.application.ports.i_event_publisher import IEventPublisher
    from credential_vault.application.ports.i_unit_of_work import IUnitOfWork
    from credential_vault.application.queries.policy_queries import (
        GetRotationPolicyQuery,
        ListRotationPoliciesQuery,
    )

logger = logging.getLogger(__name__)


class RotationPolicyApplicationService:
    """Orchestrates rotation policy CRUD with post-commit event publishing."""

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

    def _validate_rotation_fields(
        self,
        *,
        interval_days: int | None,
        max_versions_kept: int,
        notify_days_before: int,
    ) -> None:
        if interval_days is not None and not (1 <= interval_days <= 3650):
            raise ApplicationValidationError("interval_days", "must be 1-3650 or None")
        if not (1 <= max_versions_kept <= 100):
            raise ApplicationValidationError("max_versions_kept", "must be 1-100")
        if not (0 <= notify_days_before <= 90):
            raise ApplicationValidationError("notify_days_before", "must be 0-90")

    async def create_rotation_policy(self, cmd: CreateRotationPolicyCommand) -> RotationPolicyDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.principal_id, "principal_id")
        validate_str(cmd.name, "name", 256)
        self._validate_rotation_fields(
            interval_days=cmd.interval_days,
            max_versions_kept=cmd.max_versions_kept,
            notify_days_before=cmd.notify_days_before,
        )

        policy_uuid = uuid7()
        tenant_id = cmd.tenant_id
        principal = PrincipalId(cmd.principal_id)
        await self._require_manage_policy(principal, CredentialId(policy_uuid), tenant_id)

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            policy = RotationPolicy.create(
                RotationPolicyId(policy_uuid),
                tenant_id,
                cmd.name,
                cmd.interval_days,
                cmd.max_versions_kept,
                cmd.notify_days_before,
                cmd.auto_rotate,
                now,
                auto_commit=cmd.auto_commit,
                commit_window_hours=cmd.commit_window_hours,
            )
            await uow.rotation_policies.save(policy)
            await uow.commit()

        await self._publish([policy])
        return RotationPolicyDTO.from_aggregate(policy)

    async def update_rotation_policy(self, cmd: UpdateRotationPolicyCommand) -> RotationPolicyDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.policy_id, "policy_id")
        validate_uuid(cmd.principal_id, "principal_id")
        self._validate_rotation_fields(
            interval_days=cmd.interval_days,
            max_versions_kept=cmd.max_versions_kept,
            notify_days_before=cmd.notify_days_before,
        )

        tenant_id = cmd.tenant_id
        policy_id = RotationPolicyId(cmd.policy_id)
        principal = PrincipalId(cmd.principal_id)
        await self._require_manage_policy(principal, CredentialId(cmd.policy_id), tenant_id)

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            policy = await uow.rotation_policies.get_by_id(policy_id, tenant_id)
            policy.update(
                tenant_id,
                cmd.interval_days,
                cmd.max_versions_kept,
                cmd.notify_days_before,
                cmd.auto_rotate,
                principal,
                now,
                auto_commit=cmd.auto_commit,
                commit_window_hours=cmd.commit_window_hours,
            )
            await uow.rotation_policies.save(policy)
            await uow.commit()

        await self._publish([policy])
        return RotationPolicyDTO.from_aggregate(policy)

    async def delete_rotation_policy(self, cmd: DeleteRotationPolicyCommand) -> None:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.policy_id, "policy_id")
        validate_uuid(cmd.principal_id, "principal_id")

        tenant_id = cmd.tenant_id
        policy_id = RotationPolicyId(cmd.policy_id)
        principal = PrincipalId(cmd.principal_id)
        await self._require_manage_policy(principal, CredentialId(cmd.policy_id), tenant_id)

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            policy = await uow.rotation_policies.get_by_id(policy_id, tenant_id)
            policy.delete(tenant_id, principal, now)
            await uow.rotation_policies.delete(policy_id, tenant_id)
            await uow.commit()

        await self._publish([policy])

    async def get_rotation_policy(self, qry: GetRotationPolicyQuery) -> RotationPolicyDTO:
        validate_uuid(qry.tenant_id, "tenant_id")
        validate_uuid(qry.policy_id, "policy_id")
        validate_uuid(qry.principal_id, "principal_id")

        tenant_id = qry.tenant_id
        policy_id = RotationPolicyId(qry.policy_id)
        await self._require_manage_policy(
            PrincipalId(qry.principal_id),
            CredentialId(qry.policy_id),
            tenant_id,
        )

        async with self._uow_factory() as uow:
            policy = await uow.rotation_policies.get_by_id(policy_id, tenant_id)
        return RotationPolicyDTO.from_aggregate(policy)

    async def list_rotation_policies(
        self, qry: ListRotationPoliciesQuery
    ) -> list[RotationPolicyDTO]:
        validate_uuid(qry.tenant_id, "tenant_id")
        validate_uuid(qry.principal_id, "principal_id")

        tenant_id = qry.tenant_id
        resource_id = CredentialId(uuid7())
        await self._require_manage_policy(PrincipalId(qry.principal_id), resource_id, tenant_id)

        async with self._uow_factory() as uow:
            policies = await uow.rotation_policies.list_by_tenant(tenant_id)
        return [RotationPolicyDTO.from_aggregate(policy) for policy in policies]
