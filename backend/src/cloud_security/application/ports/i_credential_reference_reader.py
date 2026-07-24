"""ICredentialReferenceReader — the read-side extension point for a
future persistence-backed Credential Integration store (M45D), mirroring
`IAssetReader` (M45B). No concrete implementation exists in this
milestone — `InMemoryCredentialReferenceRegistry` serves reads directly
this milestone; this port exists for a future infrastructure milestone
to swap in real storage without changing the application service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.application.dtos.credential_reference_record import (
        CredentialReferenceRecord,
    )
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        CredentialAssociationId,
        TenantId,
    )


class ICredentialReferenceReader(Protocol):
    def get(
        self, tenant_id: TenantId, association_id: CredentialAssociationId
    ) -> CredentialReferenceRecord | None: ...

    def list(
        self, tenant_id: TenantId, account_id: AccountId | None = None
    ) -> Sequence[CredentialReferenceRecord]: ...
