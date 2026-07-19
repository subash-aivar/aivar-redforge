"""IVaultBackendRepository ABC."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from credential_vault.domain.aggregates.vault_backend import VaultBackend
    from credential_vault.domain.value_objects.identifiers import TenantId, VaultBackendId


class IVaultBackendRepository(ABC):
    @abstractmethod
    async def save(self, backend: VaultBackend) -> None:
        """Persist vault backend."""

    @abstractmethod
    async def get_by_id(
        self, backend_id: VaultBackendId, tenant_id: TenantId
    ) -> VaultBackend:
        """Raises VaultBackendNotFound."""

    @abstractmethod
    async def get_default(self, tenant_id: TenantId) -> VaultBackend | None:
        """Returns the backend with is_default=True, or None if not set."""

    @abstractmethod
    async def delete(self, backend_id: VaultBackendId, tenant_id: TenantId) -> None:
        """Raises VaultBackendInUse if credentials exist with this backend_id."""

    @abstractmethod
    async def list_by_tenant(self, tenant_id: TenantId) -> list[VaultBackend]:
        """List backends for tenant."""
