"""Application queries for threat_actor_intel (M51.1 Phase 2)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from threat_actor_intel.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class GetThreatActorQuery:
    threat_actor_id: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ListThreatActorsQuery:
    status: str | None = None
    origin: str | None = None
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ListAssociationsForTenantQuery:
    tenant_id: TenantId
    threat_actor_id: str | None = None
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class GetThreatActorAssociationQuery:
    tenant_id: TenantId
    association_id: str
    actor_roles: tuple[str, ...] = ()
