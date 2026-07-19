"""ICredentialRepository ABC."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from credential_vault.domain.aggregates.credential import Credential
    from credential_vault.domain.value_objects.credential_name import CredentialName
    from credential_vault.domain.value_objects.identifiers import (
        CredentialId,
        ExpirationPolicyId,
        RotationPolicyId,
        TenantId,
    )
    from credential_vault.domain.value_objects.states import CredentialState


class ICredentialRepository(ABC):
    @abstractmethod
    async def save(self, credential: Credential) -> None:
        """Persist or update a Credential aggregate."""

    @abstractmethod
    async def get_by_id(
        self, credential_id: CredentialId, tenant_id: TenantId
    ) -> Credential:
        """Raises CredentialNotFound if not found or tenant_id mismatch."""

    @abstractmethod
    async def get_by_name(
        self, name: CredentialName, tenant_id: TenantId
    ) -> Credential:
        """Raises CredentialNotFound if not found."""

    @abstractmethod
    async def exists_by_name(
        self, name: CredentialName, tenant_id: TenantId
    ) -> bool:
        """Used for uniqueness check before create."""

    @abstractmethod
    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        states: list[CredentialState] | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Credential]:
        """Returns credentials filtered by states. Max limit: 1000."""

    @abstractmethod
    async def list_with_rotation_policy(
        self,
        policy_id: RotationPolicyId,
        tenant_id: TenantId,
    ) -> list[CredentialId]:
        """Used to enforce PolicyInUse on policy delete."""

    @abstractmethod
    async def list_with_expiration_policy(
        self,
        policy_id: ExpirationPolicyId,
        tenant_id: TenantId,
    ) -> list[CredentialId]:
        """Used to enforce PolicyInUse on policy delete."""
