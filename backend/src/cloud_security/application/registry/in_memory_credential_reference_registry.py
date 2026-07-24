"""InMemoryCredentialReferenceRegistry — the one concrete registry
this milestone implements (M45D). Stores `CredentialAssociation`
aggregates in-memory, keyed by `association_id`, with a secondary
uniqueness constraint of one *active* association per
`(tenant_id, account_id, provider_id)`. No persistence, no DI
container wiring, no Credential Vault calls."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_security.application.exceptions import DuplicateCredentialAttachmentError
from cloud_security.domain.value_objects.enums import CredentialAssociationStatus

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.domain.aggregates.credential_association import CredentialAssociation
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        CredentialAssociationId,
        ProviderId,
        TenantId,
    )


class InMemoryCredentialReferenceRegistry:
    def __init__(self) -> None:
        self._by_association_id: dict[str, CredentialAssociation] = {}
        self._active_by_tenant_account_provider: dict[tuple[str, str, str], str] = {}

    def register(self, association: CredentialAssociation) -> None:
        key = (
            str(association.tenant_id),
            str(association.account_id),
            str(association.provider_id),
        )
        if key in self._active_by_tenant_account_provider:
            raise DuplicateCredentialAttachmentError(
                association.account_id, association.provider_id
            )
        self._by_association_id[str(association.association_id)] = association
        self._active_by_tenant_account_provider[key] = str(association.association_id)

    def get(
        self, tenant_id: TenantId, association_id: CredentialAssociationId
    ) -> CredentialAssociation | None:
        association = self._by_association_id.get(str(association_id))
        if association is None or association.tenant_id != tenant_id:
            return None
        return association

    def get_active_for_account_provider(
        self, tenant_id: TenantId, account_id: AccountId, provider_id: ProviderId
    ) -> CredentialAssociation | None:
        key = (str(tenant_id), str(account_id), str(provider_id))
        association_id = self._active_by_tenant_account_provider.get(key)
        if association_id is None:
            return None
        return self._by_association_id.get(association_id)

    def list(
        self, tenant_id: TenantId, account_id: AccountId | None = None
    ) -> Sequence[CredentialAssociation]:
        results = (a for a in self._by_association_id.values() if a.tenant_id == tenant_id)
        if account_id is not None:
            results = (a for a in results if a.account_id == account_id)
        return tuple(results)

    def is_attached(
        self, tenant_id: TenantId, account_id: AccountId, provider_id: ProviderId
    ) -> bool:
        return (str(tenant_id), str(account_id), str(provider_id)) in (
            self._active_by_tenant_account_provider
        )

    def release(self, association: CredentialAssociation) -> None:
        """Free the `(tenant, account, provider)` uniqueness slot once
        an association is detached — called by the application service
        after `CredentialAssociation.detach()` succeeds, so a fresh
        `attach` for the same pair can proceed. `detach()` leaves the
        old association's own record intact for audit; only the
        registry's "currently active" index entry is released here."""
        if association.status != CredentialAssociationStatus.DETACHED:
            return
        key = (
            str(association.tenant_id),
            str(association.account_id),
            str(association.provider_id),
        )
        self._active_by_tenant_account_provider.pop(key, None)
