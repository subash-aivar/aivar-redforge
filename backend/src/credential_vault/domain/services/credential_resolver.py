"""CredentialResolverService — orchestrates secret resolution in the domain."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import uuid7

from credential_vault.domain.events.credential_events import (
    BreakGlassAccessed,
    CredentialAccessed,
)
from credential_vault.domain.exceptions.domain_exceptions import ActiveVersionNotFound
from credential_vault.domain.value_objects.payloads import ResolvedSecret

if TYPE_CHECKING:
    from credential_vault.domain.aggregates.credential import Credential
    from credential_vault.domain.entities.credential_version import CredentialVersion
    from credential_vault.domain.ports.i_encryption_port import IEncryptionPort
    from credential_vault.domain.ports.i_key_management_port import IKeyManagementPort
    from credential_vault.domain.ports.i_permission_port import IPermissionPort
    from credential_vault.domain.services.access_control_policy import (
        AccessControlPolicyService,
    )
    from credential_vault.domain.services.break_glass_service import BreakGlassService
    from credential_vault.domain.value_objects.access_context import AccessContext


class CredentialResolverService:
    """
    Orchestrates the full secret resolution flow within the domain.
    Delegates encryption and key management to ports. Enforces fail-closed audit.
    """

    def __init__(
        self,
        encryption_port: IEncryptionPort,
        key_mgmt_port: IKeyManagementPort,
        permission_port: IPermissionPort,
        access_control: AccessControlPolicyService,
        break_glass_svc: BreakGlassService,
    ) -> None:
        self._encryption_port = encryption_port
        self._key_mgmt_port = key_mgmt_port
        self._permission_port = permission_port
        self._access_control = access_control
        self._break_glass_svc = break_glass_svc

    async def resolve(
        self,
        credential: Credential,
        active_version: CredentialVersion,
        context: AccessContext,
    ) -> ResolvedSecret:
        if context.break_glass:
            await self._break_glass_svc.validate_break_glass(credential, context)
        else:
            await self._access_control.assert_can_read(credential, context)

        if not active_version.is_resolvable():
            raise ActiveVersionNotFound(credential.credential_id)

        # DEK zeroization is the IEncryptionPort contract responsibility.
        # Caller-side zeroing of immutable bytes only clears a copy and is ineffective.
        dek = await self._key_mgmt_port.unwrap_dek(active_version.key_envelope)
        plaintext = await self._encryption_port.decrypt(
            active_version.encrypted_payload, dek
        )

        now = datetime.now(UTC)
        if context.break_glass:
            credential.record_domain_event(
                BreakGlassAccessed(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=credential.tenant_id,
                    aggregate_id=str(credential.credential_id),
                    aggregate_type="Credential",
                    credential_id=credential.credential_id,
                    version_id=active_version.version_id,
                    principal_id=context.principal_id,
                    justification=context.justification or "",
                    approvers=0,
                )
            )
        else:
            credential.record_domain_event(
                CredentialAccessed(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=credential.tenant_id,
                    aggregate_id=str(credential.credential_id),
                    aggregate_type="Credential",
                    credential_id=credential.credential_id,
                    version_id=active_version.version_id,
                    principal_id=context.principal_id,
                    client_ip=context.client_ip,
                    purpose=context.purpose,
                    break_glass=False,
                )
            )

        _ = self._permission_port
        return ResolvedSecret(
            plaintext=plaintext,
            credential_id=credential.credential_id,
            version_id=active_version.version_id,
            resolved_at=now,
        )
