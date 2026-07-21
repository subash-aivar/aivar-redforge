"""Supply chain CQRS query dataclasses."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class GetModelProvenanceQuery:
    tenant_id: UUID
    provenance_id: UUID
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GetMBOMByProvenanceQuery:
    tenant_id: UUID
    provenance_id: UUID
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GetIntegrityStatusForAssetQuery:
    tenant_id: UUID
    asset_id: UUID


@dataclass(frozen=True, slots=True)
class ListRecentDiscoveryScansQuery:
    tenant_id: UUID
    limit: int
    actor_roles: tuple[str, ...]
