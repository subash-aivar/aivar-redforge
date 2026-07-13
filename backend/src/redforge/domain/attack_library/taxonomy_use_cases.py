"""Use cases for the Attack Taxonomy sub-context.

These are the validated entry points for tree mutations that need
repository access to enforce invariants the AttackTaxonomyNode entity
itself cannot check alone: key uniqueness (needs to see every other
node) and cycle prevention on reparent (needs the proposed new parent's
full ancestor chain). No switch statements, no hardcoded registry —
every operation is generic tree logic driven by repository queries.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.attack_library.taxonomy import (
    AttackTaxonomyNode,
    DuplicateTaxonomyKeyError,
    TaxonomyCycleError,
    TaxonomyNodeNotFoundError,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from redforge.domain.attack_library.taxonomy import AttackTaxonomyRepository


@dataclass(frozen=True, slots=True)
class TaxonomyNodeResult:
    """Read-only representation of an AttackTaxonomyNode."""

    id: str
    key: str
    name: str
    description: str
    parent_id: str | None
    is_active: bool
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, node: AttackTaxonomyNode) -> TaxonomyNodeResult:
        return cls(
            id=str(node.id),
            key=str(node.key),
            name=node.name,
            description=node.description,
            parent_id=str(node.parent_id) if node.parent_id else None,
            is_active=node.is_active,
            created_at=node.timestamps.created_at.isoformat(),
            updated_at=node.timestamps.updated_at.isoformat(),
        )


class CreateTaxonomyNodeUseCase:
    """Create a new taxonomy node, enforcing key uniqueness and that
    any declared parent actually exists."""

    def __init__(self, repository: AttackTaxonomyRepository) -> None:
        self._repository = repository

    async def execute(
        self,
        key: str,
        name: str,
        description: str,
        parent_id: str | None = None,
    ) -> TaxonomyNodeResult:
        if await self._repository.get_by_key(key) is not None:
            raise DuplicateTaxonomyKeyError(key)

        parent_entity_id: EntityId | None = None
        if parent_id is not None:
            parent_entity_id = EntityId.from_string(parent_id)
            if await self._repository.get_by_id(parent_entity_id) is None:
                raise TaxonomyNodeNotFoundError(parent_id)

        node = AttackTaxonomyNode.create(
            key=key, name=name, description=description, parent_id=parent_entity_id,
        )
        await self._repository.save(node)
        return TaxonomyNodeResult.from_entity(node)


class MoveTaxonomyNodeUseCase:
    """Reparent a taxonomy node, rejecting any move that would create a
    cycle (making the node its own ancestor)."""

    def __init__(self, repository: AttackTaxonomyRepository) -> None:
        self._repository = repository

    async def execute(self, node_id: str, new_parent_id: str | None) -> TaxonomyNodeResult:
        entity_id = EntityId.from_string(node_id)
        node = await self._repository.get_by_id(entity_id)
        if node is None:
            raise TaxonomyNodeNotFoundError(node_id)

        new_parent_entity_id: EntityId | None = None
        if new_parent_id is not None:
            new_parent_entity_id = EntityId.from_string(new_parent_id)
            if new_parent_entity_id == entity_id:
                raise TaxonomyCycleError(node_id, new_parent_id)
            new_parent = await self._repository.get_by_id(new_parent_entity_id)
            if new_parent is None:
                raise TaxonomyNodeNotFoundError(new_parent_id)

            ancestors = await self._repository.get_ancestors(new_parent_entity_id)
            if entity_id in {ancestor.id for ancestor in ancestors}:
                raise TaxonomyCycleError(node_id, new_parent_id)

        node.reparent(new_parent_entity_id)
        await self._repository.save(node)
        return TaxonomyNodeResult.from_entity(node)


class GetTaxonomyPathUseCase:
    """Return the breadcrumb path from root to a node, inclusive —
    e.g. [Prompt Injection, Indirect, Via Tool Output]."""

    def __init__(self, repository: AttackTaxonomyRepository) -> None:
        self._repository = repository

    async def execute(self, node_id: str) -> list[TaxonomyNodeResult]:
        entity_id = EntityId.from_string(node_id)
        node = await self._repository.get_by_id(entity_id)
        if node is None:
            raise TaxonomyNodeNotFoundError(node_id)
        ancestors = await self._repository.get_ancestors(entity_id)
        return [TaxonomyNodeResult.from_entity(n) for n in (*ancestors, node)]


class ListChildrenUseCase:
    """List the direct children of a node, or the roots if node_id is None."""

    def __init__(self, repository: AttackTaxonomyRepository) -> None:
        self._repository = repository

    async def execute(self, node_id: str | None) -> list[TaxonomyNodeResult]:
        parent_id = EntityId.from_string(node_id) if node_id is not None else None
        children = await self._repository.get_children(parent_id)
        return [TaxonomyNodeResult.from_entity(n) for n in children]


class ListDescendantsUseCase:
    """List every node transitively beneath a node — the subtree used
    to answer "every technique under Prompt Injection, at any depth."
    """

    def __init__(self, repository: AttackTaxonomyRepository) -> None:
        self._repository = repository

    async def execute(self, node_id: str) -> list[TaxonomyNodeResult]:
        entity_id = EntityId.from_string(node_id)
        if await self._repository.get_by_id(entity_id) is None:
            raise TaxonomyNodeNotFoundError(node_id)
        descendants = await self._repository.get_descendants(entity_id)
        return [TaxonomyNodeResult.from_entity(n) for n in descendants]


class DeprecateTaxonomyNodeUseCase:
    """Deprecate a taxonomy node. Existing attacks may still reference
    it (deprecation is not deletion); it should no longer be offered
    for new classification."""

    def __init__(self, repository: AttackTaxonomyRepository) -> None:
        self._repository = repository

    async def execute(self, node_id: str) -> TaxonomyNodeResult:
        entity_id = EntityId.from_string(node_id)
        node = await self._repository.get_by_id(entity_id)
        if node is None:
            raise TaxonomyNodeNotFoundError(node_id)
        node.deprecate()
        await self._repository.save(node)
        return TaxonomyNodeResult.from_entity(node)
