"""ICredentialReferenceWriter — the write-side extension point for a
future persistence-backed Credential Integration store (M45D),
mirroring `IAssetWriter` (M45B). No concrete implementation exists in
this milestone — the application service operates directly on the
`CredentialAssociation` aggregate it is handed and the in-memory
registry; this port exists for a future infrastructure milestone to
persist the resulting record, not for this milestone to call. Never
writes secret material — `CredentialReferenceRecord` carries reference
metadata only."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from cloud_security.application.dtos.credential_reference_record import (
        CredentialReferenceRecord,
    )
    from cloud_security.domain.value_objects.identifiers import CredentialAssociationId, TenantId


class ICredentialReferenceWriter(Protocol):
    def save(self, record: CredentialReferenceRecord) -> None: ...

    def delete(self, tenant_id: TenantId, association_id: CredentialAssociationId) -> None: ...
