"""Agent governance CQRS query dataclasses."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from ai_agent_governance.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class GetEnvelopeQuery:
    tenant_id: TenantId
    envelope_id: UUID
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GetEnvelopeAdvisoriesQuery:
    tenant_id: TenantId
    envelope_id: UUID
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ListUnreviewedDeviationsQuery:
    tenant_id: TenantId
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CountRecentDeviationsForAssetQuery:
    tenant_id: TenantId
    asset_id: UUID
    limit: int = 100
