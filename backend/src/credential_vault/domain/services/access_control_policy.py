"""AccessControlPolicyService — domain access invariants via IPermissionPort."""

from __future__ import annotations

from typing import TYPE_CHECKING

from credential_vault.domain.exceptions.domain_exceptions import (
    AccessDenied,
    CredentialIsDeleted,
    CredentialIsExpired,
    CredentialIsRevoked,
    InvalidStateTransition,
)
from credential_vault.domain.ports.i_permission_port import IPermissionPort
from credential_vault.domain.value_objects.states import CredentialState

if TYPE_CHECKING:
    from credential_vault.domain.aggregates.credential import Credential
    from credential_vault.domain.value_objects.access_context import AccessContext


class AccessControlPolicyService:
    """
    Domain-level access rules. Delegates permission resolution to IPermissionPort.
    Does not implement ACL storage — only enforces domain invariants around access.
    """

    def __init__(self, permission_port: IPermissionPort) -> None:
        self._permission_port = permission_port

    async def assert_can_read(
        self,
        credential: Credential,
        context: AccessContext,
    ) -> None:
        if credential.state == CredentialState.REVOKED:
            raise CredentialIsRevoked(credential.credential_id)
        if credential.state == CredentialState.EXPIRED:
            raise CredentialIsExpired(credential.credential_id, credential.updated_at)
        if credential.state == CredentialState.DELETED:
            raise CredentialIsDeleted(credential.credential_id)
        if credential.state not in {CredentialState.ACTIVE, CredentialState.ROTATING}:
            raise AccessDenied(
                context.principal_id,
                IPermissionPort.PERMISSION_READ,
                credential.credential_id,
            )
        allowed = await self._permission_port.has_permission(
            context.principal_id,
            credential.credential_id,
            IPermissionPort.PERMISSION_READ,
            credential.tenant_id,
        )
        if not allowed:
            raise AccessDenied(
                context.principal_id,
                IPermissionPort.PERMISSION_READ,
                credential.credential_id,
            )

    async def assert_can_write(
        self,
        credential: Credential,
        context: AccessContext,
    ) -> None:
        allowed = await self._permission_port.has_permission(
            context.principal_id,
            credential.credential_id,
            IPermissionPort.PERMISSION_WRITE,
            credential.tenant_id,
        )
        if not allowed:
            raise AccessDenied(
                context.principal_id,
                IPermissionPort.PERMISSION_WRITE,
                credential.credential_id,
            )

    async def assert_can_rotate(
        self,
        credential: Credential,
        context: AccessContext,
    ) -> None:
        if credential.state != CredentialState.ACTIVE:
            raise InvalidStateTransition(
                current=credential.state.value,
                attempted="rotate",
                credential_id=credential.credential_id,
            )
        allowed = await self._permission_port.has_permission(
            context.principal_id,
            credential.credential_id,
            IPermissionPort.PERMISSION_ROTATE,
            credential.tenant_id,
        )
        if not allowed:
            raise AccessDenied(
                context.principal_id,
                IPermissionPort.PERMISSION_ROTATE,
                credential.credential_id,
            )

    async def assert_can_revoke(
        self,
        credential: Credential,
        context: AccessContext,
    ) -> None:
        allowed = await self._permission_port.has_permission(
            context.principal_id,
            credential.credential_id,
            IPermissionPort.PERMISSION_REVOKE,
            credential.tenant_id,
        )
        if not allowed:
            raise AccessDenied(
                context.principal_id,
                IPermissionPort.PERMISSION_REVOKE,
                credential.credential_id,
            )

    async def assert_can_emergency_revoke(
        self,
        credential: Credential,
        context: AccessContext,
    ) -> None:
        allowed = await self._permission_port.has_permission(
            context.principal_id,
            credential.credential_id,
            IPermissionPort.PERMISSION_EMERGENCY_REVOKE,
            credential.tenant_id,
        )
        if not allowed:
            raise AccessDenied(
                context.principal_id,
                IPermissionPort.PERMISSION_EMERGENCY_REVOKE,
                credential.credential_id,
            )

    async def assert_can_delete(
        self,
        credential: Credential,
        context: AccessContext,
    ) -> None:
        if credential.state in {CredentialState.ACTIVE, CredentialState.ROTATING}:
            raise InvalidStateTransition(
                current=credential.state.value,
                attempted="delete",
                credential_id=credential.credential_id,
            )
        allowed = await self._permission_port.has_permission(
            context.principal_id,
            credential.credential_id,
            IPermissionPort.PERMISSION_DELETE,
            credential.tenant_id,
        )
        if not allowed:
            raise AccessDenied(
                context.principal_id,
                IPermissionPort.PERMISSION_DELETE,
                credential.credential_id,
            )
