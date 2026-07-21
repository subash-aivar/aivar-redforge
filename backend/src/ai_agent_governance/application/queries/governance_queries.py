"""Agent governance CQRS query dataclasses."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class GetEnvelopeQuery:
    tenant_id: UUID
    envelope_id: UUID
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GetEnvelopeAdvisoriesQuery:
    tenant_id: UUID
    envelope_id: UUID
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ListUnreviewedDeviationsQuery:
    tenant_id: UUID
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CountRecentDeviationsForAssetQuery:
    tenant_id: UUID
    asset_id: UUID
    limit: int = 100
