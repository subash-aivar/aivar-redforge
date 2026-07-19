"""Vault backend query dataclasses (CQRS read side)."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID  # noqa: TC003 — runtime type for frozen dataclass fields


@dataclass(frozen=True, slots=True)
class GetVaultBackendQuery:
    tenant_id: UUID
    backend_id: UUID
    principal_id: UUID


@dataclass(frozen=True, slots=True)
class ListVaultBackendsQuery:
    tenant_id: UUID
    principal_id: UUID
