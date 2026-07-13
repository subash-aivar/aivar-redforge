"""Attack Taxonomy — the hierarchical, unlimited-depth classification
tree for AI attack techniques.

Why this exists alongside AttackCategory (value_objects.py): AttackCategory
is a small, closed, top-level StrEnum — deliberately so, since it changes
rarely and every value is load-bearing across the codebase (queries,
dashboards, compliance mappings). But the mission for this bounded
context requires "unlimited future techniques" and explicitly forbids
hardcoded registries — a use case a closed enum structurally cannot
satisfy, no matter how many members it grows. AttackTaxonomyNode is the
answer: a plain, persisted, arbitrarily-deep tree of classification
nodes, authored as data (via CreateTaxonomyNodeUseCase), not code. A
new sub-technique, or a whole new technique family, is a new row, never
a new enum member or a deploy.

AttackDefinition.taxonomy_node_id is additive to `category`, not a
replacement for it: `category` remains the stable top-level filter;
taxonomy_node_id provides arbitrarily deep sub-classification beneath
it (e.g. category=PROMPT_INJECTION, taxonomy path could be
Prompt Injection > Indirect > Via Tool Output > Via MCP Resource).

Protocol-first: AttackTaxonomyRepository is a Protocol. No switch
statements — every traversal (ancestors, descendants, path) is generic
tree recursion driven by repository queries, not a dispatch on node
identity. No infrastructure concerns leak into this module.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Protocol, Self, runtime_checkable

from redforge.core.exceptions import ConflictError, NotFoundError, ValidationError
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps

if TYPE_CHECKING:
    from redforge.domain.attack_library.value_objects import FrameworkMapping

_KEY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_]*[a-z0-9]$|^[a-z0-9]$")


class TaxonomyNodeNotFoundError(NotFoundError):
    """Raised when a taxonomy node cannot be located."""

    def __init__(self, identifier: str) -> None:
        super().__init__(resource="AttackTaxonomyNode", identifier=identifier)


class DuplicateTaxonomyKeyError(ConflictError):
    """Raised when a taxonomy node key is already in use.

    Keys are unique platform-wide (not just among siblings) — a stable,
    human-readable, code-independent identifier a FrameworkMapping or
    an external system can reference without knowing the ULID.
    """

    def __init__(self, key: str) -> None:
        super().__init__(message=f"Taxonomy key '{key}' is already in use")
        self.key = key


class TaxonomyCycleError(ValidationError):
    """Raised when reparenting a node would create a cycle (making a
    node its own ancestor, directly or transitively)."""

    def __init__(self, node_id: str, new_parent_id: str) -> None:
        super().__init__(
            message=(
                f"Cannot reparent '{node_id}' under '{new_parent_id}': "
                "would create a cycle"
            ),
            details={"node_id": node_id, "new_parent_id": new_parent_id},
        )
        self.node_id = node_id
        self.new_parent_id = new_parent_id


class TaxonomyNodeInactiveError(ValidationError):
    """Raised when mutating an already-deprecated node in a way that
    requires it to be active (e.g. deprecating it again)."""

    def __init__(self, node_id: str) -> None:
        super().__init__(
            message=f"Taxonomy node '{node_id}' is already deprecated",
            details={"node_id": node_id},
        )
        self.node_id = node_id


class TaxonomyNodeKey:
    """A stable, unique, human-readable identifier for a taxonomy node.

    Lowercase snake_case, 1-64 chars. Distinct from the node's ULID
    identity: the key is the thing a FrameworkMapping, an import
    script, or a human curator references; the ULID is the thing the
    database and other aggregates reference.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("Taxonomy key must not be empty")
        if len(normalized) > 64:
            raise ValueError("Taxonomy key must not exceed 64 characters")
        if not _KEY_PATTERN.match(normalized):
            raise ValueError(
                f"Taxonomy key '{value}' must be lowercase snake_case "
                "(letters, digits, underscores only, no leading/trailing "
                "underscore)"
            )
        self._value = normalized

    def __str__(self) -> str:
        return self._value

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TaxonomyNodeKey):
            return self._value == other._value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._value)

    def __repr__(self) -> str:
        return f"TaxonomyNodeKey({self._value!r})"


class AttackTaxonomyNode:
    """A single node in the attack taxonomy tree.

    Invariants:
    - Always has a key, name, and description.
    - A root node has parent_id=None; every other node has a parent.
    - Deprecated nodes are still referenceable (existing attacks may
      still point at them — deprecation is not deletion) but should not
      be offered for NEW classification going forward.
    - This entity does not know its own depth, siblings, or descendants
      — those require repository queries (see AttackTaxonomyRepository
      and taxonomy_use_cases). Keeping the entity ignorant of the rest
      of the tree keeps it trivially testable and keeps cycle detection
      (which needs the whole ancestor chain) correctly out of the
      entity and in the use case that has repository access.
    """

    __slots__ = (
        "_description",
        "_framework_mappings",
        "_id",
        "_is_active",
        "_key",
        "_name",
        "_parent_id",
        "_timestamps",
    )

    def __init__(
        self,
        id: EntityId,
        key: TaxonomyNodeKey,
        name: str,
        description: str,
        parent_id: EntityId | None,
        is_active: bool,
        framework_mappings: set[FrameworkMapping],
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._key = key
        self._name = name
        self._description = description
        self._parent_id = parent_id
        self._is_active = is_active
        self._framework_mappings = framework_mappings
        self._timestamps = timestamps

    @classmethod
    def create(
        cls,
        key: str,
        name: str,
        description: str,
        parent_id: EntityId | None = None,
    ) -> Self:
        if not name or len(name.strip()) < 2:
            raise ValueError("Taxonomy node name must be at least 2 characters")
        return cls(
            id=EntityId.generate(),
            key=TaxonomyNodeKey(key),
            name=name.strip(),
            description=description.strip(),
            parent_id=parent_id,
            is_active=True,
            framework_mappings=set(),
            timestamps=AuditTimestamps.create(),
        )

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def key(self) -> TaxonomyNodeKey:
        return self._key

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def parent_id(self) -> EntityId | None:
        return self._parent_id

    @property
    def is_root(self) -> bool:
        return self._parent_id is None

    @property
    def is_active(self) -> bool:
        return self._is_active

    @property
    def framework_mappings(self) -> frozenset[FrameworkMapping]:
        return frozenset(self._framework_mappings)

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    # ─── Behavior ─────────────────────────────────────────────────────────

    def rename(self, name: str, description: str | None = None) -> None:
        if not name or len(name.strip()) < 2:
            raise ValueError("Taxonomy node name must be at least 2 characters")
        self._name = name.strip()
        if description is not None:
            self._description = description.strip()
        self._touch()

    def reparent(self, new_parent_id: EntityId | None) -> None:
        """Move this node under a new parent (or to root, with None).

        Does NOT check for cycles — that requires walking the proposed
        new parent's ancestor chain, which requires repository access
        this entity does not have. Use
        taxonomy_use_cases.MoveTaxonomyNodeUseCase, which performs that
        check before calling this.
        """
        self._parent_id = new_parent_id
        self._touch()

    def deprecate(self) -> None:
        if not self._is_active:
            raise TaxonomyNodeInactiveError(str(self._id))
        self._is_active = False
        self._touch()

    def reactivate(self) -> None:
        self._is_active = True
        self._touch()

    def map_to_framework(self, mapping: FrameworkMapping) -> None:
        self._framework_mappings.add(mapping)
        self._touch()

    def remove_framework_mapping(self, mapping: FrameworkMapping) -> None:
        self._framework_mappings.discard(mapping)
        self._touch()

    # ─── Private ──────────────────────────────────────────────────────────

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AttackTaxonomyNode):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"AttackTaxonomyNode(id={self._id}, key={self._key}, "
            f"name={self._name!r}, parent_id={self._parent_id})"
        )


@runtime_checkable
class AttackTaxonomyRepository(Protocol):
    """Port for Attack Taxonomy Node persistence and tree queries.

    Every traversal operation a use case needs is expressed here as a
    query the repository answers — no in-memory whole-tree loading, no
    switch statement over node identity. An infrastructure adapter is
    free to implement `get_descendants` as a recursive CTE, an
    adjacency-list walk, or a materialized closure table; the domain
    only depends on the shape of the answer.
    """

    async def get_by_id(self, node_id: EntityId) -> AttackTaxonomyNode | None:
        """Retrieve a node by its identity."""
        ...

    async def get_by_key(self, key: str) -> AttackTaxonomyNode | None:
        """Retrieve a node by its unique human-readable key."""
        ...

    async def get_children(self, parent_id: EntityId | None) -> list[AttackTaxonomyNode]:
        """List direct children of a node. parent_id=None lists roots."""
        ...

    async def get_ancestors(self, node_id: EntityId) -> list[AttackTaxonomyNode]:
        """Return the chain from root to (but not including) the given
        node, ordered root-first. Empty list for a root node."""
        ...

    async def get_descendants(self, node_id: EntityId) -> list[AttackTaxonomyNode]:
        """Return every node transitively parented under `node_id`, in
        no particular guaranteed order."""
        ...

    async def save(self, node: AttackTaxonomyNode) -> None:
        """Persist a new or updated taxonomy node."""
        ...
