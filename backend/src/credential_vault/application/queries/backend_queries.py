"""Vault backend query dataclasses (CQRS read side)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID  # noqa: TC003 — runtime type for frozen dataclass fields

if TYPE_CHECKING:
    from credential_vault.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class GetVaultBackendQuery:
    tenant_id: TenantId
    backend_id: UUID
    principal_id: TenantId


@dataclass(frozen=True, slots=True)
class ListVaultBackendsQuery:
    tenant_id: TenantId
    principal_id: TenantId
