from __future__ import annotations

from typing import Protocol

from integration_hub.domain.value_objects.credentials import CredentialRef, ResolvedCredential


class CredentialVaultPort(Protocol):
    async def resolve(self, ref: CredentialRef, tenant_id: str) -> ResolvedCredential: ...


class CredentialResolutionService:
    def __init__(self, vault: CredentialVaultPort) -> None:
        self._vault = vault

    async def resolve(self, ref: CredentialRef, tenant_id: str) -> ResolvedCredential:
        if ref.tenant_id != tenant_id:
            raise ValueError("credential tenant mismatch")
        return await self._vault.resolve(ref, tenant_id)
