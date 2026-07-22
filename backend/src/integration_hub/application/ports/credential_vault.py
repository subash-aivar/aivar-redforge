from __future__ import annotations

from typing import Protocol

from integration_hub.domain.value_objects.credentials import CredentialRef, ResolvedCredential


class ICredentialVaultPort(Protocol):
    async def resolve(self, ref: CredentialRef, tenant_id: str) -> ResolvedCredential: ...
