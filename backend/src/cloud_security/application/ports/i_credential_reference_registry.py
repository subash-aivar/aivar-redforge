"""ICredentialReferenceRegistry — the registration/lookup contract for
the Credential Integration layer's own store of `CredentialAssociation`
aggregates (M45D), mirroring `IProviderRegistry` (M45C): the registry
*is* the framework's in-memory store, not a plug-in resolver.
`InMemoryCredentialReferenceRegistry` (M45D) is this milestone's one
concrete implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.domain.aggregates.credential_association import CredentialAssociation
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        CredentialAssociationId,
        ProviderId,
        TenantId,
    )


class ICredentialReferenceRegistry(Protocol):
    def register(self, association: CredentialAssociation) -> None:
        """Raises `DuplicateCredentialAttachmentError` if the same
        `(tenant_id, account_id, provider_id)` already has an active
        association."""
        ...

    def get(
        self, tenant_id: TenantId, association_id: CredentialAssociationId
    ) -> CredentialAssociation | None: ...

    def get_active_for_account_provider(
        self, tenant_id: TenantId, account_id: AccountId, provider_id: ProviderId
    ) -> CredentialAssociation | None: ...

    def list(
        self, tenant_id: TenantId, account_id: AccountId | None = None
    ) -> Sequence[CredentialAssociation]: ...

    def is_attached(
        self, tenant_id: TenantId, account_id: AccountId, provider_id: ProviderId
    ) -> bool: ...

    def release(self, association: CredentialAssociation) -> None:
        """Free the `(tenant, account, provider)` uniqueness slot once
        `association` has transitioned to `DETACHED`, so a fresh
        `attach` for the same pair can proceed. A no-op if the
        association is not detached."""
        ...
