"""Concrete adapter implementing `ICredentialVaultPort` by delegating to the
real `credential_vault` bounded context's `CredentialApplicationService`.

This is the ONLY place in `integration_hub` that is allowed to import from
`credential_vault` — every application service must depend on the port
(`integration_hub.application.ports.credential_vault.ICredentialVaultPort`)
instead, keeping the dependency direction pointed at `integration_hub`'s own
abstraction rather than another bounded context's concrete types.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from integration_hub.domain.value_objects.credentials import ResolvedCredential


class CredentialVaultAdapter:
    """Wraps the real `credential_vault` `CredentialApplicationService`
    behind `ICredentialVaultPort`. Behavior (which command, which fields,
    tenant checks) is unchanged from the previous inline call sites — this
    only relocates the cross-context knowledge to a single adapter."""

    def __init__(self, credential_service: Any) -> None:
        self._svc = credential_service

    async def resolve(
        self,
        *,
        tenant_id: Any,
        credential_id: UUID,
        principal_id: Any,
        purpose: str,
    ) -> ResolvedCredential:
        from credential_vault.application.commands.credential_commands import (
            ResolveCredentialCommand,
        )

        resolved = await self._svc.resolve_credential(
            ResolveCredentialCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
                purpose=purpose,
            )
        )
        secret = resolved.plaintext_secret.decode("utf-8")
        return ResolvedCredential(
            credential_type=purpose,
            secret_value=secret,
            expires_at=getattr(resolved, "expires_at", None),
        )

    async def create(
        self,
        *,
        tenant_id: Any,
        name: str,
        category: str,
        subtype: str,
        owner_principal_id: UUID,
        vault_backend_id: UUID,
        plaintext_secret: bytes,
        description: str | None,
        tags: dict[str, str],
    ) -> str:
        from credential_vault.application.commands.credential_commands import (
            CreateCredentialCommand,
        )

        cred_dto = await self._svc.create_credential(
            CreateCredentialCommand(
                tenant_id=tenant_id,
                name=name,
                category=category,
                subtype=subtype,
                schema_id=None,
                owner_principal_id=owner_principal_id,
                vault_backend_id=vault_backend_id,
                plaintext_secret=plaintext_secret,
                description=description,
                tags=tags,
            )
        )
        return str(cred_dto.credential_id)
