"""IRotationPolicyRepository ABC."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from credential_vault.domain.aggregates.rotation_policy import RotationPolicy
    from credential_vault.domain.value_objects.identifiers import RotationPolicyId, TenantId


class IRotationPolicyRepository(ABC):
    @abstractmethod
    async def save(self, policy: RotationPolicy) -> None:
        """Raises DuplicatePolicyName if name already exists for tenant."""

    @abstractmethod
    async def get_by_id(
        self, policy_id: RotationPolicyId, tenant_id: TenantId
    ) -> RotationPolicy:
        """Raises PolicyNotFound."""

    @abstractmethod
    async def delete(self, policy_id: RotationPolicyId, tenant_id: TenantId) -> None:
        """Raises PolicyInUse if any credential references this policy_id."""

    @abstractmethod
    async def list_by_tenant(self, tenant_id: TenantId) -> list[RotationPolicy]:
        """List rotation policies for tenant."""
