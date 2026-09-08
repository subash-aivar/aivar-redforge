"""In-memory fakes for intelligence_relationships application-layer
tests (M51.4 Phase C1). No ORM, no real I/O — pure Python
collections."""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

from intelligence_relationships.application.ports.i_attack_pattern_identity_port import (
    IAttackPatternIdentityPort,
)
from intelligence_relationships.application.ports.i_event_publisher import IEventPublisher
from intelligence_relationships.application.ports.i_ioc_identity_port import IIocIdentityPort
from intelligence_relationships.application.ports.i_relationship_repository import (
    IIntelligenceRelationshipRepository,
)
from intelligence_relationships.application.ports.i_threat_actor_identity_port import (
    IThreatActorIdentityPort,
)
from intelligence_relationships.application.ports.i_unit_of_work import IUnitOfWork
from intelligence_relationships.domain.policies.identity_policy import identity_key

if TYPE_CHECKING:
    from intelligence_relationships.domain.aggregates.intelligence_relationship import (
        IntelligenceRelationship,
    )
    from intelligence_relationships.domain.events.base import BaseDomainEvent
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


def _tenant_key(tenant_id: TenantId | None) -> str:
    return "" if tenant_id is None else str(tenant_id)


class InMemoryRelationshipRepository(IIntelligenceRelationshipRepository):
    def __init__(self) -> None:
        self._by_id: dict[str, IntelligenceRelationship] = {}

    async def save(self, relationship: IntelligenceRelationship) -> None:
        self._by_id[str(relationship.relationship_id)] = relationship

    async def get(
        self, tenant_id: TenantId | None, relationship_id: IntelligenceRelationshipId
    ) -> IntelligenceRelationship | None:
        relationship = self._by_id.get(str(relationship_id))
        if relationship is None or _tenant_key(relationship.tenant_id) != _tenant_key(tenant_id):
            return None
        return relationship

    async def get_any(
        self, relationship_id: IntelligenceRelationshipId
    ) -> IntelligenceRelationship | None:
        return self._by_id.get(str(relationship_id))

    async def get_by_identity(
        self,
        tenant_id: TenantId | None,
        relationship_type: RelationshipType,
        source_entity: EntityRef,
        target_entity: EntityRef,
    ) -> IntelligenceRelationship | None:
        candidate = identity_key(relationship_type, source_entity, target_entity)
        for relationship in self._by_id.values():
            if (
                _tenant_key(relationship.tenant_id) == _tenant_key(tenant_id)
                and relationship.identity_key == candidate
            ):
                return relationship
        return None

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
    ) -> list[IntelligenceRelationship]:
        results = [
            r for r in self._by_id.values() if _tenant_key(r.tenant_id) == _tenant_key(tenant_id)
        ]
        if relationship_type is not None:
            results = [r for r in results if r.relationship_type is relationship_type]
        if lifecycle_status is not None:
            results = [r for r in results if r.lifecycle_status is lifecycle_status]
        if epistemic_state is not None:
            results = [r for r in results if r.epistemic_state is epistemic_state]
        if source_entity_id is not None:
            results = [r for r in results if r.source_entity.entity_id == source_entity_id]
        if target_entity_id is not None:
            results = [r for r in results if r.target_entity.entity_id == target_entity_id]
        results = sorted(results, key=lambda r: r.created_at, reverse=True)
        return results[offset : offset + limit]


class FakeUnitOfWork(IUnitOfWork):
    def __init__(self, repo: InMemoryRelationshipRepository, *, fail_commit: bool = False) -> None:
        self.relationships = repo
        self._fail_commit = fail_commit
        self.committed = False
        self.rolled_back = False

    async def commit(self) -> None:
        if self._fail_commit:
            raise RuntimeError("simulated commit failure")
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        if exc_type is not None:
            await self.rollback()


class RecordingEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.published_batches: list[list[BaseDomainEvent]] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.published_batches.append(list(events))

    @property
    def all_published(self) -> list[BaseDomainEvent]:
        return [event for batch in self.published_batches for event in batch]


class FakeIocIdentityPort(IIocIdentityPort):
    def __init__(self, known: set[str] | None = None) -> None:
        self.known = known if known is not None else set()

    async def exists(self, ioc_id: str) -> bool:
        return ioc_id in self.known


class FakeThreatActorIdentityPort(IThreatActorIdentityPort):
    def __init__(self, known: set[str] | None = None) -> None:
        self.known = known if known is not None else set()

    async def exists(self, threat_actor_id: str) -> bool:
        return threat_actor_id in self.known


class FakeAttackPatternIdentityPort(IAttackPatternIdentityPort):
    def __init__(self, known: set[str] | None = None) -> None:
        self.known = known if known is not None else set()

    async def exists(self, attack_pattern_id: str) -> bool:
        return attack_pattern_id in self.known
