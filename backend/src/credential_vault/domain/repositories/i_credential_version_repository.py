"""ICredentialVersionRepository ABC."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from credential_vault.domain.entities.credential_version import CredentialVersion
    from credential_vault.domain.value_objects.identifiers import (
        CredentialId,
        TenantId,
        VersionId,
    )
    from credential_vault.domain.value_objects.states import VersionState


class ICredentialVersionRepository(ABC):
    @abstractmethod
    async def save(self, version: CredentialVersion) -> None:
        """Persist a new CredentialVersion."""

    @abstractmethod
    async def get_by_id(
        self, version_id: VersionId, tenant_id: TenantId
    ) -> CredentialVersion:
        """Raises VersionNotFound if not found or tenant_id mismatch."""

    @abstractmethod
    async def get_active_version(
        self, credential_id: CredentialId, tenant_id: TenantId
    ) -> CredentialVersion:
        """Raises ActiveVersionNotFound if no ACTIVE version exists."""

    @abstractmethod
    async def list_by_credential(
        self,
        credential_id: CredentialId,
        tenant_id: TenantId,
        states: list[VersionState] | None = None,
    ) -> list[CredentialVersion]:
        """Returns versions in ascending version_number order."""

    @abstractmethod
    async def atomic_promote(
        self,
        new_version: CredentialVersion,
        supersede_version_id: VersionId | None,
        tenant_id: TenantId,
    ) -> None:
        """Atomically promote new version and supersede previous ACTIVE."""

    @abstractmethod
    async def update(self, version: CredentialVersion) -> None:
        """Used for rewrap_key() and revoke() mutations."""

    @abstractmethod
    async def count_superseded(
        self, credential_id: CredentialId, tenant_id: TenantId
    ) -> int:
        """Used by rotation policy to enforce max_versions_kept."""
