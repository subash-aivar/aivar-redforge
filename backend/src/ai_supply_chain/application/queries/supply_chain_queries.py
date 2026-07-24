"""Supply chain CQRS query dataclasses."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from ai_supply_chain.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class GetModelProvenanceQuery:
    tenant_id: TenantId
    provenance_id: UUID
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GetMBOMByProvenanceQuery:
    tenant_id: TenantId
    provenance_id: UUID
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GetIntegrityStatusForAssetQuery:
    tenant_id: TenantId
    asset_id: UUID


@dataclass(frozen=True, slots=True)
class ListRecentDiscoveryScansQuery:
    tenant_id: TenantId
    limit: int
    actor_roles: tuple[str, ...]
