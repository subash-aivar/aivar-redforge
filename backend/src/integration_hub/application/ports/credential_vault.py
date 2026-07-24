from __future__ import annotations

from typing import Any, Protocol
from uuid import UUID

from integration_hub.domain.value_objects.credentials import ResolvedCredential


class ICredentialVaultPort(Protocol):
    """Application-layer boundary onto the `credential_vault` bounded
    context. Concrete adapters own all knowledge of `credential_vault`'s
    command/DTO shapes (`ResolveCredentialCommand`, `CreateCredentialCommand`,
    etc.) — application services in `integration_hub` must depend on this
    Protocol only, never import from `credential_vault` directly.

    `tenant_id`/`principal_id` are typed `Any` deliberately: at call sites
    they are `integration_hub`'s own `TenantId` (`=EntityId`, ULID-backed),
    which is a structurally different type than `credential_vault`'s own
    `TenantId`. The concrete adapter is the only place that hands these
    values to `credential_vault`'s commands, so it — not this Protocol —
    is where any real type reconciliation would belong."""

    async def resolve(
        self,
        *,
        tenant_id: Any,
        credential_id: UUID,
        principal_id: Any,
        purpose: str,
    ) -> ResolvedCredential: ...

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
    ) -> str: ...
