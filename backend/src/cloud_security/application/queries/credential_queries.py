"""Immutable CQRS query objects for Credential Integration (M45D)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        CredentialAssociationId,
        TenantId,
    )


@dataclass(frozen=True, slots=True)
class GetCredentialReferenceQuery:
    tenant_id: TenantId
    association_id: CredentialAssociationId


@dataclass(frozen=True, slots=True)
class ListCredentialReferencesQuery:
    tenant_id: TenantId
    account_id: AccountId | None = None


@dataclass(frozen=True, slots=True)
class ListAccountsWithoutCredentialsQuery:
    tenant_id: TenantId
    account_ids: tuple[AccountId, ...] = field(default_factory=tuple)
