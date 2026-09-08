"""IIntelligenceRelationshipRepository — implementation-independent (no
ORM/DB types), M51.4 Phase C1. `tenant_id=None` addresses the global
scope; a real `TenantId` addresses that tenant's own scope only. A
concrete adapter must never return a record whose `tenant_id` does not
exactly match the requested scope, mirroring
`IAttackPatternRepository`'s exact not-found-semantics discipline."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from intelligence_relationships.domain.aggregates.intelligence_relationship import (
        IntelligenceRelationship,
    )
    from intelligence_relationships.domain.value_objects.entity_ref import EntityRef
    from intelligence_relationships.domain.value_objects.enums import (
        EpistemicState,
        RelationshipLifecycleStatus,
        RelationshipType,
    )
    from intelligence_relationships.domain.value_objects.identifiers import (
        IntelligenceRelationshipId,
        TenantId,
    )


class IIntelligenceRelationshipRepository(ABC):
    @abstractmethod
    async def save(self, relationship: IntelligenceRelationship) -> None: ...

    @abstractmethod
    async def get(
        self, tenant_id: TenantId | None, relationship_id: IntelligenceRelationshipId
    ) -> IntelligenceRelationship | None: ...

    @abstractmethod
    async def get_any(
        self, relationship_id: IntelligenceRelationshipId
    ) -> IntelligenceRelationship | None:
        """Unscoped lookup by ID only — used exclusively to resolve a
        relationship's ownership scope (its `tenant_id`) for the API
        layer's ownership-based authorization decision. The caller must
        authorize before using anything from the returned aggregate
        beyond `.tenant_id`."""
        ...

    @abstractmethod
    async def get_by_identity(
        self,
        tenant_id: TenantId | None,
        relationship_type: RelationshipType,
        source_entity: EntityRef,
        target_entity: EntityRef,
    ) -> IntelligenceRelationship | None: ...

    @abstractmethod
    async def list(
        self,
        tenant_id: TenantId | None,
        relationship_type: RelationshipType | None = None,
        lifecycle_status: RelationshipLifecycleStatus | None = None,
        epistemic_state: EpistemicState | None = None,
        source_entity_id: str | None = None,
        target_entity_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[IntelligenceRelationship]: ...
