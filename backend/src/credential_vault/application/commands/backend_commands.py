"""Vault backend command dataclasses (CQRS write side)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID  # noqa: TC003 — runtime type for frozen dataclass fields

if TYPE_CHECKING:
    from credential_vault.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class RegisterVaultBackendCommand:
    tenant_id: TenantId
    principal_id: TenantId
    name: str
    backend_type: str
    config: dict[str, str]
    is_default: bool


@dataclass(frozen=True, slots=True)
class DeleteVaultBackendCommand:
    tenant_id: TenantId
    backend_id: UUID
    principal_id: TenantId
