"""IApprovalPort — multi-party approval workflow queries."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from credential_vault.domain.value_objects.identifiers import (
        CredentialId,
        PrincipalId,
        TenantId,
    )


class IApprovalPort(ABC):
    """
    Queries the approval workflow subsystem.
    Used for break-glass and recovery operations that require multi-party approval.
    """

    @abstractmethod
    async def is_approved(
        self,
        credential_id: CredentialId,
        principal_id: PrincipalId,
        operation: str,
        tenant_id: TenantId,
    ) -> bool:
        """
        Returns True if the required approval quorum has been met.
        Returns False if no approval exists or quorum not met.
        """

    @abstractmethod
    async def get_approver_count(
        self,
        credential_id: CredentialId,
        operation: str,
        tenant_id: TenantId,
    ) -> tuple[int, int]:
        """Returns (actual_approvers, required_approvers)."""
