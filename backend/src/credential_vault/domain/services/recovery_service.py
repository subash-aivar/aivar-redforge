"""RecoveryService — validates recovery preconditions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from credential_vault.domain.exceptions.domain_exceptions import (
    InsufficientApprovers,
    InvalidStateTransition,
    RecoveryVersionInvalid,
    TenantMismatch,
)
from credential_vault.domain.value_objects.states import CredentialState, VersionState

if TYPE_CHECKING:
    from credential_vault.domain.aggregates.credential import Credential
    from credential_vault.domain.entities.credential_version import CredentialVersion
    from credential_vault.domain.ports.i_approval_port import IApprovalPort
    from credential_vault.domain.value_objects.access_context import AccessContext


class RecoveryService:
    """
    Validates recovery preconditions and selects the recovery version.
    Pure domain logic. Does not persist.
    """

    def __init__(self, approval_port: IApprovalPort) -> None:
        self._approval_port = approval_port

    async def validate_recovery(
        self,
        credential: Credential,
        target_version: CredentialVersion,
        context: AccessContext,
    ) -> None:
        if credential.state != CredentialState.REVOKED:
            raise InvalidStateTransition(
                current=credential.state.value,
                attempted="recover",
                credential_id=credential.credential_id,
            )
        if target_version.credential_id != credential.credential_id:
            raise RecoveryVersionInvalid(
                target_version.version_id,
                "credential_id mismatch",
            )
        if target_version.tenant_id != credential.tenant_id:
            raise TenantMismatch(
                expected=credential.tenant_id,
                actual=target_version.tenant_id,
            )
        if target_version.version_state not in {
            VersionState.SUPERSEDED,
            VersionState.REVOKED,
        }:
            raise RecoveryVersionInvalid(
                target_version.version_id,
                f"state {target_version.version_state.value} not recoverable",
            )
        approved = await self._approval_port.is_approved(
            credential.credential_id,
            context.principal_id,
            "RECOVERY",
            credential.tenant_id,
        )
        if not approved:
            actual, required = await self._approval_port.get_approver_count(
                credential.credential_id,
                "RECOVERY",
                credential.tenant_id,
            )
            raise InsufficientApprovers(
                required=required,
                actual=actual,
                credential_id=credential.credential_id,
            )
