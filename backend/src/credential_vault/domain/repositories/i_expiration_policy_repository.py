"""IExpirationPolicyRepository ABC."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from credential_vault.domain.aggregates.expiration_policy import ExpirationPolicy
    from credential_vault.domain.value_objects.identifiers import (
        ExpirationPolicyId,
        TenantId,
    )


class IExpirationPolicyRepository(ABC):
    @abstractmethod
    async def save(self, policy: ExpirationPolicy) -> None:
        """Raises DuplicatePolicyName if name already exists for tenant."""

    @abstractmethod
    async def get_by_id(
        self, policy_id: ExpirationPolicyId, tenant_id: TenantId
    ) -> ExpirationPolicy:
        """Raises PolicyNotFound."""

    @abstractmethod
    async def delete(
        self, policy_id: ExpirationPolicyId, tenant_id: TenantId
    ) -> None:
        """Raises PolicyInUse if any credential references this policy_id."""

    @abstractmethod
    async def list_by_tenant(self, tenant_id: TenantId) -> list[ExpirationPolicy]:
        """List expiration policies for tenant."""
