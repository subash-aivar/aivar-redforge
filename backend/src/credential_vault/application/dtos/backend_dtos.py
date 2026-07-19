"""Vault backend DTOs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from credential_vault.domain.aggregates.vault_backend import VaultBackend


@dataclass(frozen=True, slots=True)
class VaultBackendDTO:
    backend_id: str
    tenant_id: str
    name: str
    backend_type: str
    is_default: bool
    created_at: str
    updated_at: str
    version: int

    @classmethod
    def from_aggregate(cls, backend: VaultBackend) -> Self:
        return cls(
            backend_id=str(backend.backend_id),
            tenant_id=str(backend.tenant_id),
            name=backend.name,
            backend_type=backend.backend_type.value,
            is_default=backend.is_default,
            created_at=backend.created_at.isoformat(),
            updated_at=backend.updated_at.isoformat(),
            version=backend.version,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "backend_id": self.backend_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "backend_type": self.backend_type,
            "is_default": self.is_default,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "version": self.version,
        }
