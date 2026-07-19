"""ApprovalWorkflowAdapter — quorum checks against approval_requests table."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from sqlalchemy import text

from credential_vault.domain.ports.i_approval_port import IApprovalPort

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from credential_vault.domain.value_objects.identifiers import (
        CredentialId,
        PrincipalId,
        TenantId,
    )


class ApprovalWorkflowAdapter(IApprovalPort):
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        required_quorum: int | None = None,
    ) -> None:
        self._session_factory = session_factory
        default_quorum = int(os.environ.get("CREDENTIAL_VAULT_APPROVAL_QUORUM", "2"))
        self._required = required_quorum if required_quorum is not None else default_quorum

    async def is_approved(
        self,
        credential_id: CredentialId,
        principal_id: PrincipalId,
        operation: str,
        tenant_id: TenantId,
    ) -> bool:
        _ = principal_id
        actual, required = await self.get_approver_count(credential_id, operation, tenant_id)
        return actual >= required

    async def get_approver_count(
        self,
        credential_id: CredentialId,
        operation: str,
        tenant_id: TenantId,
    ) -> tuple[int, int]:
        async with self._session_factory() as session:
            result = await session.execute(
                text(
                    """
                    SELECT COUNT(*) FROM credential_vault_approval_requests
                    WHERE credential_id = :cid AND operation = :op
                      AND tenant_id = :tid AND approved_at IS NOT NULL
                      AND expires_at > NOW()
                    """
                ),
                {
                    "cid": credential_id.value,
                    "op": operation,
                    "tid": tenant_id.value,
                },
            )
            actual = int(result.scalar_one())
        return actual, self._required
