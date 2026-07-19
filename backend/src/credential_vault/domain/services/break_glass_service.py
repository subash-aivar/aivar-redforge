"""BreakGlassService — validates break-glass access preconditions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from credential_vault.domain.exceptions.domain_exceptions import (
    BreakGlassJustificationRequired,
    CredentialIsDeleted,
    InsufficientApprovers,
)
from credential_vault.domain.value_objects.states import CredentialState

if TYPE_CHECKING:
    from credential_vault.domain.aggregates.credential import Credential
    from credential_vault.domain.ports.i_approval_port import IApprovalPort
    from credential_vault.domain.value_objects.access_context import AccessContext


class BreakGlassService:
    """
    Validates break-glass access preconditions.
    Break-glass bypasses normal access control but still requires justification
    and approval. Audit trail is mandatory and uses WAL fallback.
    """

    def __init__(self, approval_port: IApprovalPort) -> None:
        self._approval_port = approval_port

    async def validate_break_glass(
        self,
        credential: Credential,
        context: AccessContext,
    ) -> None:
        if not context.break_glass:
            raise BreakGlassJustificationRequired(credential.credential_id)
        if context.justification is None or len(context.justification) == 0:
            raise BreakGlassJustificationRequired(credential.credential_id)
        if credential.state == CredentialState.DELETED:
            raise CredentialIsDeleted(credential.credential_id)
        approved = await self._approval_port.is_approved(
            credential.credential_id,
            context.principal_id,
            "BREAK_GLASS",
            credential.tenant_id,
        )
        if not approved:
            actual, required = await self._approval_port.get_approver_count(
                credential.credential_id,
                "BREAK_GLASS",
                credential.tenant_id,
            )
            raise InsufficientApprovers(
                required=required,
                actual=actual,
                credential_id=credential.credential_id,
            )
