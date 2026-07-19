"""Vault backend command dataclasses (CQRS write side)."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID  # noqa: TC003 — runtime type for frozen dataclass fields


@dataclass(frozen=True, slots=True)
class RegisterVaultBackendCommand:
    tenant_id: UUID
    principal_id: UUID
    name: str
    backend_type: str
    config: dict[str, str]
    is_default: bool


@dataclass(frozen=True, slots=True)
class DeleteVaultBackendCommand:
    tenant_id: UUID
    backend_id: UUID
    principal_id: UUID
