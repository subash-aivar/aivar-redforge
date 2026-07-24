"""CredentialReferenceRecord — the read-only projection of a
`CredentialAssociation` returned by the application layer (M45D).
Carries reference *metadata* only (credential id + type tag,
attach/rotate timestamps) — never secret material."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from cloud_security.domain.value_objects.enums import CredentialAssociationStatus


@dataclass(frozen=True, slots=True)
class CredentialReferenceRecord:
    association_id: str
    tenant_id: str
    account_id: str
    provider_id: str
    active_credential_id: str
    active_credential_type: str
    previous_credential_id: str | None
    previous_credential_type: str | None
    status: CredentialAssociationStatus
    attached_at: datetime
    rotated_at: datetime | None
