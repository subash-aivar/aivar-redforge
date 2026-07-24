"""Credential lifecycle application service (command side)."""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid7

from credential_vault.application._validation import validate_str, validate_uuid
from credential_vault.application.dtos.credential_dtos import CredentialDTO, ResolvedSecretDTO
from credential_vault.application.exceptions import (
    ApplicationAuditFailure,
    ApplicationPortError,
    ApplicationValidationError,
)
from credential_vault.domain.aggregates.audit_log import AuditLog
from credential_vault.domain.aggregates.credential import Credential
from credential_vault.domain.entities.audit_entry import AuditEntry
from credential_vault.domain.entities.credential_version import CredentialVersion
from credential_vault.domain.exceptions.domain_exceptions import (
    AccessDenied,
    CredentialAlreadyExists,
    InvalidStateTransition,
)
from credential_vault.domain.ports.i_permission_port import IPermissionPort
from credential_vault.domain.value_objects.access_context import AccessContext
from credential_vault.domain.value_objects.audit_types import (
    AuditOperation,
    AuditOutcome,
    RotationTrigger,
)
from credential_vault.domain.value_objects.credential_name import CredentialName
from credential_vault.domain.value_objects.credential_type import (
    CredentialCategory,
    CredentialType,
)
from credential_vault.domain.value_objects.identifiers import (
    AuditEntryId,
    AuditLogId,
    CredentialId,
    ExpirationPolicyId,
    PrincipalId,
    RotationPolicyId,
    TenantId,
    VaultBackendId,
    VersionId,
)
from credential_vault.domain.value_objects.rotation_context import RotationContext
from credential_vault.domain.value_objects.states import VersionState

if TYPE_CHECKING:
    from collections.abc import Callable

    from credential_vault.application.commands.credential_commands import (
        AbortRotationCommand,
        AttachExpirationPolicyCommand,
        AttachRotationPolicyCommand,
        CommitRotationCommand,
        CreateCredentialCommand,
        DetachExpirationPolicyCommand,
        DetachRotationPolicyCommand,
        DisableCredentialCommand,
        EmergencyRevokeCommand,
        EnableCredentialCommand,
        ExpireCredentialCommand,
        HardDeleteCredentialCommand,
        RecoverCredentialCommand,
        ResolveCredentialCommand,
        RevokeCredentialCommand,
        RollbackVersionCommand,
        RotateCredentialCommand,
        UpdateCredentialMetadataCommand,
    )
    from credential_vault.application.ports.i_event_publisher import IEventPublisher
    from credential_vault.application.ports.i_unit_of_work import IUnitOfWork
    from credential_vault.domain.ports.i_approval_port import IApprovalPort
    from credential_vault.domain.ports.i_encryption_port import IEncryptionPort
    from credential_vault.domain.ports.i_key_management_port import IKeyManagementPort
    from credential_vault.domain.services.access_control_policy import (
        AccessControlPolicyService,
    )
    from credential_vault.domain.services.break_glass_service import BreakGlassService
    from credential_vault.domain.services.credential_resolver import (
        CredentialResolverService,
    )
    from credential_vault.domain.services.recovery_service import RecoveryService

logger = logging.getLogger(__name__)


class CredentialApplicationService:
    """Orchestrates credential lifecycle mutations with audit and event publishing."""

    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        key_mgmt_port: IKeyManagementPort,
        encryption_port: IEncryptionPort,
        permission_port: IPermissionPort,
        approval_port: IApprovalPort,
        access_control: AccessControlPolicyService,
        break_glass_svc: BreakGlassService,
        recovery_svc: RecoveryService,
        resolver_svc: CredentialResolverService,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher
        self._key_mgmt_port = key_mgmt_port
        self._encryption_port = encryption_port
        self._permission_port = permission_port
        self._approval_port = approval_port
        self._access_control = access_control
        self._break_glass_svc = break_glass_svc
        self._recovery_svc = recovery_svc
        self._resolver_svc = resolver_svc

    def _build_access_context(
        self,
        principal_id: TenantId,
        purpose: str,
        client_ip: str | None,
        request_id: str | None,
        break_glass: bool,
        justification: str | None,
    ) -> AccessContext:
        try:
            return AccessContext(
                PrincipalId(principal_id.value.to_uuid()),
                purpose,
                client_ip,
                request_id,
                break_glass,
                justification,
            )
        except ValueError as exc:
            raise ApplicationValidationError("access_context", str(exc)) from exc

    async def _get_audit_log(
        self,
        uow: IUnitOfWork,
        credential_id: CredentialId,
        tenant_id: TenantId,
    ) -> AuditLog:
        return await uow.audit_logs.get_by_credential(credential_id, tenant_id)

    def _make_audit_entry(
        self,
        audit_log_id: AuditLogId,
        credential_id: CredentialId,
        tenant_id: TenantId,
        operation: AuditOperation,
        principal_id: PrincipalId,
        detail: str,
        client_ip: str | None = None,
        request_id: str | None = None,
    ) -> AuditEntry:
        return AuditEntry(
            entry_id=AuditEntryId(uuid7()),
            audit_log_id=audit_log_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            operation=operation,
            outcome=AuditOutcome.SUCCESS,
            principal_id=principal_id,
            occurred_at=datetime.now(UTC),
            version_id=None,
            client_ip=client_ip,
            request_id=request_id,
            detail=detail,
            state_before=None,
            state_after=None,
        )

    async def _write_audit_and_commit(
        self,
        uow: IUnitOfWork,
        audit_log_id: AuditLogId,
        entry: AuditEntry,
        tenant_id: TenantId,
    ) -> None:
        try:
            await uow.audit_logs.append_entry(audit_log_id, entry, tenant_id)
        except Exception as exc:
            raise ApplicationAuditFailure(f"Audit write failed: {exc}") from exc
        await uow.commit()

    async def _publish(self, aggregates: list[Any]) -> None:
        events: list[Any] = []
        for aggregate in aggregates:
            events.extend(aggregate.pop_events())
        try:
            await self._event_publisher.publish_batch(events)
        except Exception as exc:
            logger.warning("Event publication failed: %s", exc)

    async def create_credential(self, cmd: CreateCredentialCommand) -> CredentialDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.owner_principal_id, "owner_principal_id")
        validate_uuid(cmd.vault_backend_id, "vault_backend_id")
        if cmd.schema_id is not None:
            validate_uuid(cmd.schema_id, "schema_id")

        validate_str(cmd.name, "name", 256)
        if not re.fullmatch(r"[\w\-\./ ]+", cmd.name):
            raise ApplicationValidationError("name", "contains invalid characters")

        try:
            category = CredentialCategory(cmd.category)
        except ValueError as exc:
            raise ApplicationValidationError("category", str(exc)) from exc

        validate_str(cmd.subtype, "subtype", 64)
        if not re.fullmatch(r"[A-Z0-9_-]+", cmd.subtype):
            raise ApplicationValidationError("subtype", "must match [A-Z0-9_-]+")

        if category == CredentialCategory.CUSTOM and cmd.schema_id is None:
            raise ApplicationValidationError("schema_id", "required for CUSTOM category")
        if category != CredentialCategory.CUSTOM and cmd.schema_id is not None:
            raise ApplicationValidationError("schema_id", "only valid for CUSTOM category")

        if not cmd.plaintext_secret:
            raise ApplicationValidationError("plaintext_secret", "must not be empty")

        if len(cmd.tags) > 50:
            raise ApplicationValidationError("tags", "max 50 tags")
        for key, value in cmd.tags.items():
            if len(key) > 100:
                raise ApplicationValidationError("tags", "tag key max 100 chars")
            if len(value) > 1000:
                raise ApplicationValidationError("tags", "tag value max 1000 chars")
        if cmd.description is not None and len(cmd.description) > 2048:
            raise ApplicationValidationError("description", "max 2048 chars")

        credential_id = CredentialId(uuid7())
        tenant_id = cmd.tenant_id
        owner = PrincipalId(cmd.owner_principal_id.value.to_uuid())

        allowed = await self._permission_port.has_permission(
            owner,
            credential_id,
            IPermissionPort.PERMISSION_WRITE,
            tenant_id,
        )
        if not allowed:
            raise AccessDenied(owner, IPermissionPort.PERMISSION_WRITE, credential_id)

        try:
            dek_bytes, key_envelope = await self._key_mgmt_port.generate_dek()
        except Exception as exc:
            raise ApplicationPortError("key_management", exc) from exc

        try:
            encrypted_payload = await self._encryption_port.encrypt(cmd.plaintext_secret, dek_bytes)
        except Exception as exc:
            raise ApplicationPortError("encryption", exc) from exc

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            version_id = VersionId(uuid7())
            audit_log_id = AuditLogId(uuid7())

            exists = await uow.credentials.exists_by_name(CredentialName(cmd.name), tenant_id)
            if exists:
                raise CredentialAlreadyExists(CredentialName(cmd.name), tenant_id)

            await uow.vault_backends.get_by_id(VaultBackendId(cmd.vault_backend_id), tenant_id)

            version = CredentialVersion(
                version_id,
                credential_id,
                tenant_id,
                1,
                encrypted_payload,
                key_envelope,
                VersionState.PENDING,
                None,
                now,
                owner,
                cmd.expires_at,
            )
            cred_type = CredentialType(category, cmd.subtype, cmd.schema_id)
            credential = Credential.create(
                credential_id,
                tenant_id,
                CredentialName(cmd.name),
                cred_type,
                owner,
                VaultBackendId(cmd.vault_backend_id),
                cmd.description,
                cmd.tags,
                now,
            )
            credential.activate(tenant_id, version_id, now)
            version.promote()
            audit_log = AuditLog.create(audit_log_id, credential_id, tenant_id, now)

            await uow.credentials.save(credential)
            await uow.versions.save(version)
            await uow.audit_logs.save(audit_log)

            entry = self._make_audit_entry(
                audit_log_id,
                credential_id,
                tenant_id,
                AuditOperation.CREATED,
                owner,
                f"credential created by {cmd.owner_principal_id}",
            )
            await self._write_audit_and_commit(uow, audit_log_id, entry, tenant_id)

        await self._publish([credential])
        return CredentialDTO.from_aggregate(credential)

    async def resolve_credential(self, cmd: ResolveCredentialCommand) -> ResolvedSecretDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.credential_id, "credential_id")
        validate_uuid(cmd.principal_id, "principal_id")
        validate_str(cmd.purpose, "purpose", 512)
        if cmd.request_id is not None:
            validate_str(cmd.request_id, "request_id", 128, allow_empty=True)
        if cmd.break_glass and not cmd.justification:
            raise ApplicationValidationError("justification", "required for break-glass access")
        if cmd.justification is not None:
            validate_str(cmd.justification, "justification", 2048)

        access_context = self._build_access_context(
            cmd.principal_id,
            cmd.purpose,
            cmd.client_ip,
            cmd.request_id,
            cmd.break_glass,
            cmd.justification,
        )

        credential_id = CredentialId(cmd.credential_id)
        tenant_id = cmd.tenant_id

        async with self._uow_factory() as uow:
            credential = await uow.credentials.get_by_id(credential_id, tenant_id)
            active_version = await uow.versions.get_active_version(credential_id, tenant_id)
            resolved_secret = await self._resolver_svc.resolve(
                credential, active_version, access_context
            )
            audit_log = await self._get_audit_log(uow, credential_id, tenant_id)

            if cmd.break_glass:
                operation = AuditOperation.BREAK_GLASS
                detail = (
                    f"justification={cmd.justification}; "
                    f"ip={cmd.client_ip}; request_id={cmd.request_id}"
                )
            else:
                operation = AuditOperation.ACCESSED
                detail = f"purpose={cmd.purpose}; ip={cmd.client_ip}; request_id={cmd.request_id}"

            entry = self._make_audit_entry(
                audit_log.audit_log_id,
                credential_id,
                tenant_id,
                operation,
                PrincipalId(cmd.principal_id.value.to_uuid()),
                detail,
                client_ip=cmd.client_ip,
                request_id=cmd.request_id,
            )
            await uow.credentials.save(credential)
            await self._write_audit_and_commit(uow, audit_log.audit_log_id, entry, tenant_id)

        await self._publish([credential])
        return ResolvedSecretDTO(
            str(credential.credential_id),
            str(active_version.version_id),
            resolved_secret.get_plaintext(),
            resolved_secret.resolved_at.isoformat(),
        )

    async def rotate_credential(self, cmd: RotateCredentialCommand) -> CredentialDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.credential_id, "credential_id")
        validate_uuid(cmd.principal_id, "principal_id")
        if cmd.policy_id is not None:
            validate_uuid(cmd.policy_id, "policy_id")
        if not cmd.new_plaintext_secret:
            raise ApplicationValidationError("new_plaintext_secret", "must not be empty")
        try:
            trigger = RotationTrigger(cmd.trigger)
        except ValueError as exc:
            raise ApplicationValidationError("trigger", str(exc)) from exc
        if cmd.notes is not None:
            validate_str(cmd.notes, "notes", 1024, allow_empty=True)

        try:
            dek_bytes, key_envelope = await self._key_mgmt_port.generate_dek()
        except Exception as exc:
            raise ApplicationPortError("key_management", exc) from exc

        try:
            encrypted_payload = await self._encryption_port.encrypt(
                cmd.new_plaintext_secret, dek_bytes
            )
        except Exception as exc:
            raise ApplicationPortError("encryption", exc) from exc

        credential_id = CredentialId(cmd.credential_id)
        tenant_id = cmd.tenant_id
        principal = PrincipalId(cmd.principal_id.value.to_uuid())
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            credential = await uow.credentials.get_by_id(credential_id, tenant_id)
            await self._access_control.assert_can_rotate(
                credential,
                AccessContext(principal, "rotation", None, None),
            )
            if credential.active_version_id is None:
                raise InvalidStateTransition(
                    current=credential.state.value,
                    attempted="begin_rotation",
                    credential_id=credential_id,
                )

            versions = await uow.versions.list_by_credential(credential_id, tenant_id)
            next_version_number = max((v.version_number for v in versions), default=0) + 1
            new_version_id = VersionId(uuid7())
            rotation_context = RotationContext(
                trigger,
                principal,
                credential.active_version_id,
                RotationPolicyId(cmd.policy_id) if cmd.policy_id else None,
                cmd.notes,
            )
            new_version = CredentialVersion(
                new_version_id,
                credential_id,
                tenant_id,
                next_version_number,
                encrypted_payload,
                key_envelope,
                VersionState.PENDING,
                rotation_context,
                now,
                principal,
                None,
            )
            credential.begin_rotation(tenant_id, new_version_id, rotation_context, now)

            await uow.versions.save(new_version)
            await uow.credentials.save(credential)

            audit_log = await self._get_audit_log(uow, credential_id, tenant_id)
            entry = self._make_audit_entry(
                audit_log.audit_log_id,
                credential_id,
                tenant_id,
                AuditOperation.ROTATION_STARTED,
                principal,
                f"trigger={cmd.trigger}; new_version_id={new_version_id}",
            )
            await self._write_audit_and_commit(uow, audit_log.audit_log_id, entry, tenant_id)

        await self._publish([credential])
        return CredentialDTO.from_aggregate(credential)

    async def commit_rotation(self, cmd: CommitRotationCommand) -> CredentialDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.credential_id, "credential_id")
        validate_uuid(cmd.principal_id, "principal_id")

        credential_id = CredentialId(cmd.credential_id)
        tenant_id = cmd.tenant_id
        principal = PrincipalId(cmd.principal_id.value.to_uuid())

        allowed = await self._permission_port.has_permission(
            principal,
            credential_id,
            IPermissionPort.PERMISSION_ROTATE,
            tenant_id,
        )
        if not allowed:
            raise AccessDenied(principal, IPermissionPort.PERMISSION_ROTATE, credential_id)

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            credential = await uow.credentials.get_by_id(credential_id, tenant_id)
            pending = await uow.versions.list_by_credential(
                credential_id,
                tenant_id,
                states=[VersionState.PENDING],
            )
            if len(pending) != 1:
                raise InvalidStateTransition(
                    current=credential.state.value,
                    attempted="commit_rotation",
                )
            new_version = pending[0]
            if credential.active_version_id is None:
                raise InvalidStateTransition(
                    current=credential.state.value,
                    attempted="commit_rotation",
                )
            old_version = await uow.versions.get_by_id(credential.active_version_id, tenant_id)

            new_version.promote()
            old_version.supersede()
            credential.commit_rotation(
                tenant_id,
                new_version.version_id,
                old_version.version_id,
                now,
            )
            await uow.versions.atomic_promote(
                new_version,
                old_version.version_id,
                tenant_id,
            )
            await uow.credentials.save(credential)

            audit_log = await self._get_audit_log(uow, credential_id, tenant_id)
            entry = self._make_audit_entry(
                audit_log.audit_log_id,
                credential_id,
                tenant_id,
                AuditOperation.ROTATION_COMMITTED,
                principal,
                (f"new_version_id={new_version.version_id}; superseded={old_version.version_id}"),
            )
            await self._write_audit_and_commit(uow, audit_log.audit_log_id, entry, tenant_id)

        await self._publish([credential])
        return CredentialDTO.from_aggregate(credential)

    async def abort_rotation(self, cmd: AbortRotationCommand) -> CredentialDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.credential_id, "credential_id")
        validate_uuid(cmd.principal_id, "principal_id")
        validate_str(cmd.reason, "reason", 1024)

        credential_id = CredentialId(cmd.credential_id)
        tenant_id = cmd.tenant_id
        principal = PrincipalId(cmd.principal_id.value.to_uuid())

        allowed = await self._permission_port.has_permission(
            principal,
            credential_id,
            IPermissionPort.PERMISSION_ROTATE,
            tenant_id,
        )
        if not allowed:
            raise AccessDenied(principal, IPermissionPort.PERMISSION_ROTATE, credential_id)

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            credential = await uow.credentials.get_by_id(credential_id, tenant_id)
            pending = await uow.versions.list_by_credential(
                credential_id,
                tenant_id,
                states=[VersionState.PENDING],
            )
            if len(pending) != 1:
                raise InvalidStateTransition(
                    current=credential.state.value,
                    attempted="abort_rotation",
                )
            aborted_version = pending[0]
            aborted_version.revoke()
            credential._pending_new_version_id = aborted_version.version_id
            credential.abort_rotation(tenant_id, cmd.reason, principal, now)

            await uow.versions.update(aborted_version)
            await uow.credentials.save(credential)

            audit_log = await self._get_audit_log(uow, credential_id, tenant_id)
            entry = self._make_audit_entry(
                audit_log.audit_log_id,
                credential_id,
                tenant_id,
                AuditOperation.ROTATION_ABORTED,
                principal,
                (f"reason={cmd.reason}; aborted_version_id={aborted_version.version_id}"),
            )
            await self._write_audit_and_commit(uow, audit_log.audit_log_id, entry, tenant_id)

        await self._publish([credential])
        return CredentialDTO.from_aggregate(credential)

    async def disable_credential(self, cmd: DisableCredentialCommand) -> CredentialDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.credential_id, "credential_id")
        validate_uuid(cmd.principal_id, "principal_id")
        validate_str(cmd.reason, "reason", 1024)

        credential_id = CredentialId(cmd.credential_id)
        tenant_id = cmd.tenant_id
        principal = PrincipalId(cmd.principal_id.value.to_uuid())

        allowed = await self._permission_port.has_permission(
            principal,
            credential_id,
            IPermissionPort.PERMISSION_WRITE,
            tenant_id,
        )
        if not allowed:
            raise AccessDenied(principal, IPermissionPort.PERMISSION_WRITE, credential_id)

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            credential = await uow.credentials.get_by_id(credential_id, tenant_id)
            credential.disable(tenant_id, principal, cmd.reason, now)
            await uow.credentials.save(credential)

            audit_log = await self._get_audit_log(uow, credential_id, tenant_id)
            entry = self._make_audit_entry(
                audit_log.audit_log_id,
                credential_id,
                tenant_id,
                AuditOperation.DISABLED,
                principal,
                f"reason={cmd.reason}",
            )
            await self._write_audit_and_commit(uow, audit_log.audit_log_id, entry, tenant_id)

        await self._publish([credential])
        return CredentialDTO.from_aggregate(credential)

    async def enable_credential(self, cmd: EnableCredentialCommand) -> CredentialDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.credential_id, "credential_id")
        validate_uuid(cmd.principal_id, "principal_id")

        credential_id = CredentialId(cmd.credential_id)
        tenant_id = cmd.tenant_id
        principal = PrincipalId(cmd.principal_id.value.to_uuid())

        allowed = await self._permission_port.has_permission(
            principal,
            credential_id,
            IPermissionPort.PERMISSION_WRITE,
            tenant_id,
        )
        if not allowed:
            raise AccessDenied(principal, IPermissionPort.PERMISSION_WRITE, credential_id)

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            credential = await uow.credentials.get_by_id(credential_id, tenant_id)
            credential.enable(tenant_id, principal, now)
            await uow.credentials.save(credential)

            audit_log = await self._get_audit_log(uow, credential_id, tenant_id)
            entry = self._make_audit_entry(
                audit_log.audit_log_id,
                credential_id,
                tenant_id,
                AuditOperation.ENABLED,
                principal,
                f"enabled by {cmd.principal_id}",
            )
            await self._write_audit_and_commit(uow, audit_log.audit_log_id, entry, tenant_id)

        await self._publish([credential])
        return CredentialDTO.from_aggregate(credential)

    async def revoke_credential(self, cmd: RevokeCredentialCommand) -> CredentialDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.credential_id, "credential_id")
        validate_uuid(cmd.principal_id, "principal_id")
        validate_str(cmd.reason, "reason", 1024)

        credential_id = CredentialId(cmd.credential_id)
        tenant_id = cmd.tenant_id
        principal = PrincipalId(cmd.principal_id.value.to_uuid())
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            credential = await uow.credentials.get_by_id(credential_id, tenant_id)
            await self._access_control.assert_can_revoke(
                credential,
                self._build_access_context(cmd.principal_id, "revoke", None, None, False, None),
            )
            credential.revoke(tenant_id, principal, cmd.reason, now)
            await uow.credentials.save(credential)

            audit_log = await self._get_audit_log(uow, credential_id, tenant_id)
            entry = self._make_audit_entry(
                audit_log.audit_log_id,
                credential_id,
                tenant_id,
                AuditOperation.REVOKED,
                principal,
                f"reason={cmd.reason}",
            )
            await self._write_audit_and_commit(uow, audit_log.audit_log_id, entry, tenant_id)

        await self._publish([credential])
        return CredentialDTO.from_aggregate(credential)

    async def emergency_revoke(self, cmd: EmergencyRevokeCommand) -> CredentialDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.credential_id, "credential_id")
        validate_uuid(cmd.principal_id, "principal_id")
        validate_str(cmd.justification, "justification", 2048)

        credential_id = CredentialId(cmd.credential_id)
        tenant_id = cmd.tenant_id
        principal = PrincipalId(cmd.principal_id.value.to_uuid())
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            credential = await uow.credentials.get_by_id(credential_id, tenant_id)
            await self._access_control.assert_can_emergency_revoke(
                credential,
                self._build_access_context(
                    cmd.principal_id,
                    "emergency_revoke",
                    None,
                    None,
                    False,
                    cmd.justification,
                ),
            )
            credential.emergency_revoke(tenant_id, principal, cmd.justification, now)
            await uow.credentials.save(credential)

            audit_log = await self._get_audit_log(uow, credential_id, tenant_id)
            entry = self._make_audit_entry(
                audit_log.audit_log_id,
                credential_id,
                tenant_id,
                AuditOperation.EMERGENCY_REVOKED,
                principal,
                f"justification={cmd.justification}",
            )
            await self._write_audit_and_commit(uow, audit_log.audit_log_id, entry, tenant_id)

        await self._publish([credential])
        return CredentialDTO.from_aggregate(credential)

    async def expire_credential(self, cmd: ExpireCredentialCommand) -> CredentialDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.credential_id, "credential_id")
        validate_uuid(cmd.principal_id, "principal_id")

        credential_id = CredentialId(cmd.credential_id)
        tenant_id = cmd.tenant_id
        principal = PrincipalId(cmd.principal_id.value.to_uuid())
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            credential = await uow.credentials.get_by_id(credential_id, tenant_id)
            credential.expire(tenant_id, now)
            await uow.credentials.save(credential)

            audit_log = await self._get_audit_log(uow, credential_id, tenant_id)
            entry = self._make_audit_entry(
                audit_log.audit_log_id,
                credential_id,
                tenant_id,
                AuditOperation.EXPIRED,
                principal,
                "system-initiated expiration",
            )
            await self._write_audit_and_commit(uow, audit_log.audit_log_id, entry, tenant_id)

        await self._publish([credential])
        return CredentialDTO.from_aggregate(credential)

    async def recover_credential(self, cmd: RecoverCredentialCommand) -> CredentialDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.credential_id, "credential_id")
        validate_uuid(cmd.principal_id, "principal_id")
        validate_uuid(cmd.target_version_id, "target_version_id")
        validate_str(cmd.justification, "justification", 2048)

        credential_id = CredentialId(cmd.credential_id)
        tenant_id = cmd.tenant_id
        principal = PrincipalId(cmd.principal_id.value.to_uuid())
        target_version_id = VersionId(cmd.target_version_id)

        allowed = await self._permission_port.has_permission(
            principal,
            credential_id,
            IPermissionPort.PERMISSION_WRITE,
            tenant_id,
        )
        if not allowed:
            raise AccessDenied(principal, IPermissionPort.PERMISSION_WRITE, credential_id)

        access_context = self._build_access_context(
            cmd.principal_id,
            "recovery",
            None,
            None,
            False,
            cmd.justification,
        )
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            credential = await uow.credentials.get_by_id(credential_id, tenant_id)
            target_version = await uow.versions.get_by_id(target_version_id, tenant_id)
            await self._recovery_svc.validate_recovery(credential, target_version, access_context)
            credential.recover(tenant_id, principal, target_version.version_id, now)
            target_version.version_state = VersionState.ACTIVE

            await uow.versions.update(target_version)
            await uow.credentials.save(credential)

            audit_log = await self._get_audit_log(uow, credential_id, tenant_id)
            entry = self._make_audit_entry(
                audit_log.audit_log_id,
                credential_id,
                tenant_id,
                AuditOperation.RECOVERED,
                principal,
                (
                    f"target_version_id={target_version.version_id}; "
                    f"justification={cmd.justification}"
                ),
            )
            await self._write_audit_and_commit(uow, audit_log.audit_log_id, entry, tenant_id)

        await self._publish([credential])
        return CredentialDTO.from_aggregate(credential)

    async def hard_delete_credential(self, cmd: HardDeleteCredentialCommand) -> None:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.credential_id, "credential_id")
        validate_uuid(cmd.principal_id, "principal_id")

        credential_id = CredentialId(cmd.credential_id)
        tenant_id = cmd.tenant_id
        principal = PrincipalId(cmd.principal_id.value.to_uuid())
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            credential = await uow.credentials.get_by_id(credential_id, tenant_id)
            await self._access_control.assert_can_delete(
                credential,
                self._build_access_context(cmd.principal_id, "delete", None, None, False, None),
            )
            credential.hard_delete(tenant_id, principal, now)
            await uow.credentials.save(credential)

            audit_log = await self._get_audit_log(uow, credential_id, tenant_id)
            entry = self._make_audit_entry(
                audit_log.audit_log_id,
                credential_id,
                tenant_id,
                AuditOperation.DELETED,
                principal,
                f"hard deleted by {cmd.principal_id}",
            )
            await self._write_audit_and_commit(uow, audit_log.audit_log_id, entry, tenant_id)

        await self._publish([credential])

    async def rollback_version(self, cmd: RollbackVersionCommand) -> CredentialDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.credential_id, "credential_id")
        validate_uuid(cmd.principal_id, "principal_id")
        validate_uuid(cmd.target_version_id, "target_version_id")

        credential_id = CredentialId(cmd.credential_id)
        tenant_id = cmd.tenant_id
        principal = PrincipalId(cmd.principal_id.value.to_uuid())
        target_version_id = VersionId(cmd.target_version_id)

        allowed = await self._permission_port.has_permission(
            principal,
            credential_id,
            IPermissionPort.PERMISSION_WRITE,
            tenant_id,
        )
        if not allowed:
            raise AccessDenied(principal, IPermissionPort.PERMISSION_WRITE, credential_id)

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            credential = await uow.credentials.get_by_id(credential_id, tenant_id)
            target_version = await uow.versions.get_by_id(target_version_id, tenant_id)
            if target_version.version_state != VersionState.SUPERSEDED:
                raise InvalidStateTransition(
                    current=target_version.version_state.value,
                    attempted="rollback",
                )
            if credential.active_version_id is None:
                raise InvalidStateTransition(
                    current=credential.state.value,
                    attempted="rollback",
                )
            current_active = await uow.versions.get_by_id(credential.active_version_id, tenant_id)
            current_active.supersede()
            target_version.version_state = VersionState.ACTIVE
            credential.rollback_version(tenant_id, target_version.version_id, principal, now)

            await uow.versions.update(current_active)
            await uow.versions.update(target_version)
            await uow.credentials.save(credential)

            audit_log = await self._get_audit_log(uow, credential_id, tenant_id)
            entry = self._make_audit_entry(
                audit_log.audit_log_id,
                credential_id,
                tenant_id,
                AuditOperation.VERSION_ROLLED_BACK,
                principal,
                f"rolled_back_to={target_version.version_id}",
            )
            await self._write_audit_and_commit(uow, audit_log.audit_log_id, entry, tenant_id)

        await self._publish([credential])
        return CredentialDTO.from_aggregate(credential)

    async def update_metadata(self, cmd: UpdateCredentialMetadataCommand) -> CredentialDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.credential_id, "credential_id")
        validate_uuid(cmd.principal_id, "principal_id")
        if cmd.description is not None and len(cmd.description) > 2048:
            raise ApplicationValidationError("description", "max 2048 chars")
        if len(cmd.tags) > 50:
            raise ApplicationValidationError("tags", "max 50 tags")
        for key, value in cmd.tags.items():
            if len(key) > 100:
                raise ApplicationValidationError("tags", "tag key max 100 chars")
            if len(value) > 1000:
                raise ApplicationValidationError("tags", "tag value max 1000 chars")

        credential_id = CredentialId(cmd.credential_id)
        tenant_id = cmd.tenant_id
        principal = PrincipalId(cmd.principal_id.value.to_uuid())

        allowed = await self._permission_port.has_permission(
            principal,
            credential_id,
            IPermissionPort.PERMISSION_WRITE,
            tenant_id,
        )
        if not allowed:
            raise AccessDenied(principal, IPermissionPort.PERMISSION_WRITE, credential_id)

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            credential = await uow.credentials.get_by_id(credential_id, tenant_id)
            changed_fields: list[str] = []
            if cmd.description != credential.description:
                changed_fields.append("description")
            if cmd.tags != credential.tags:
                changed_fields.append("tags")

            credential.update_metadata(tenant_id, cmd.description, cmd.tags, principal, now)
            await uow.credentials.save(credential)

            audit_log = await self._get_audit_log(uow, credential_id, tenant_id)
            entry = self._make_audit_entry(
                audit_log.audit_log_id,
                credential_id,
                tenant_id,
                AuditOperation.METADATA_UPDATED,
                principal,
                f"changed_fields={changed_fields}",
            )
            await self._write_audit_and_commit(uow, audit_log.audit_log_id, entry, tenant_id)

        await self._publish([credential])
        return CredentialDTO.from_aggregate(credential)

    async def attach_rotation_policy(self, cmd: AttachRotationPolicyCommand) -> CredentialDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.credential_id, "credential_id")
        validate_uuid(cmd.policy_id, "policy_id")
        validate_uuid(cmd.principal_id, "principal_id")

        credential_id = CredentialId(cmd.credential_id)
        tenant_id = cmd.tenant_id
        principal = PrincipalId(cmd.principal_id.value.to_uuid())
        policy_id = RotationPolicyId(cmd.policy_id)

        allowed = await self._permission_port.has_permission(
            principal,
            credential_id,
            IPermissionPort.PERMISSION_MANAGE_POLICY,
            tenant_id,
        )
        if not allowed:
            raise AccessDenied(principal, IPermissionPort.PERMISSION_MANAGE_POLICY, credential_id)

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            credential = await uow.credentials.get_by_id(credential_id, tenant_id)
            await uow.rotation_policies.get_by_id(policy_id, tenant_id)
            credential.attach_rotation_policy(tenant_id, policy_id, principal, now)
            await uow.credentials.save(credential)

            audit_log = await self._get_audit_log(uow, credential_id, tenant_id)
            entry = self._make_audit_entry(
                audit_log.audit_log_id,
                credential_id,
                tenant_id,
                AuditOperation.POLICY_ATTACHED,
                principal,
                f"policy_id={policy_id}; type=rotation",
            )
            await self._write_audit_and_commit(uow, audit_log.audit_log_id, entry, tenant_id)

        await self._publish([credential])
        return CredentialDTO.from_aggregate(credential)

    async def detach_rotation_policy(self, cmd: DetachRotationPolicyCommand) -> CredentialDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.credential_id, "credential_id")
        validate_uuid(cmd.principal_id, "principal_id")

        credential_id = CredentialId(cmd.credential_id)
        tenant_id = cmd.tenant_id
        principal = PrincipalId(cmd.principal_id.value.to_uuid())

        allowed = await self._permission_port.has_permission(
            principal,
            credential_id,
            IPermissionPort.PERMISSION_MANAGE_POLICY,
            tenant_id,
        )
        if not allowed:
            raise AccessDenied(principal, IPermissionPort.PERMISSION_MANAGE_POLICY, credential_id)

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            credential = await uow.credentials.get_by_id(credential_id, tenant_id)
            detached_policy_id = credential.rotation_policy_id
            credential.detach_rotation_policy(tenant_id, principal, now)
            await uow.credentials.save(credential)

            audit_log = await self._get_audit_log(uow, credential_id, tenant_id)
            entry = self._make_audit_entry(
                audit_log.audit_log_id,
                credential_id,
                tenant_id,
                AuditOperation.POLICY_DETACHED,
                principal,
                f"policy_id={detached_policy_id}; type=rotation",
            )
            await self._write_audit_and_commit(uow, audit_log.audit_log_id, entry, tenant_id)

        await self._publish([credential])
        return CredentialDTO.from_aggregate(credential)

    async def attach_expiration_policy(self, cmd: AttachExpirationPolicyCommand) -> CredentialDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.credential_id, "credential_id")
        validate_uuid(cmd.policy_id, "policy_id")
        validate_uuid(cmd.principal_id, "principal_id")

        credential_id = CredentialId(cmd.credential_id)
        tenant_id = cmd.tenant_id
        principal = PrincipalId(cmd.principal_id.value.to_uuid())
        policy_id = ExpirationPolicyId(cmd.policy_id)

        allowed = await self._permission_port.has_permission(
            principal,
            credential_id,
            IPermissionPort.PERMISSION_MANAGE_POLICY,
            tenant_id,
        )
        if not allowed:
            raise AccessDenied(principal, IPermissionPort.PERMISSION_MANAGE_POLICY, credential_id)

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            credential = await uow.credentials.get_by_id(credential_id, tenant_id)
            await uow.expiration_policies.get_by_id(policy_id, tenant_id)
            credential.attach_expiration_policy(tenant_id, policy_id, principal, now)
            await uow.credentials.save(credential)

            audit_log = await self._get_audit_log(uow, credential_id, tenant_id)
            entry = self._make_audit_entry(
                audit_log.audit_log_id,
                credential_id,
                tenant_id,
                AuditOperation.POLICY_ATTACHED,
                principal,
                f"policy_id={policy_id}; type=expiration",
            )
            await self._write_audit_and_commit(uow, audit_log.audit_log_id, entry, tenant_id)

        await self._publish([credential])
        return CredentialDTO.from_aggregate(credential)

    async def detach_expiration_policy(self, cmd: DetachExpirationPolicyCommand) -> CredentialDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.credential_id, "credential_id")
        validate_uuid(cmd.principal_id, "principal_id")

        credential_id = CredentialId(cmd.credential_id)
        tenant_id = cmd.tenant_id
        principal = PrincipalId(cmd.principal_id.value.to_uuid())

        allowed = await self._permission_port.has_permission(
            principal,
            credential_id,
            IPermissionPort.PERMISSION_MANAGE_POLICY,
            tenant_id,
        )
        if not allowed:
            raise AccessDenied(principal, IPermissionPort.PERMISSION_MANAGE_POLICY, credential_id)

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            credential = await uow.credentials.get_by_id(credential_id, tenant_id)
            detached_policy_id = credential.expiration_policy_id
            credential.detach_expiration_policy(tenant_id, principal, now)
            await uow.credentials.save(credential)

            audit_log = await self._get_audit_log(uow, credential_id, tenant_id)
            entry = self._make_audit_entry(
                audit_log.audit_log_id,
                credential_id,
                tenant_id,
                AuditOperation.POLICY_DETACHED,
                principal,
                f"policy_id={detached_policy_id}; type=expiration",
            )
            await self._write_audit_and_commit(uow, audit_log.audit_log_id, entry, tenant_id)

        await self._publish([credential])
        return CredentialDTO.from_aggregate(credential)
