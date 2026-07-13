"""Attack Knowledge Graph Projector — wires Attack Taxonomy and Attack
Relationship facts into the Knowledge Graph.

Distinct from knowledge_graph_populator.py: that module projects the
*outcome* of a validation run (org → target → provider → attack →
evidence → finding → risk), triggered after execution. This module
projects the *authoring-time* structure of the Attack Knowledge Model
itself — the taxonomy tree and the relationships between attack
definitions — triggered whenever a taxonomy node or attack relationship
is created, independent of whether that attack has ever been executed.

This sprint does not implement execution; this projector is what makes
"Support graph traversal" (the Attack Relationships requirement) a
reality without building a second graph engine — it reuses the
existing KnowledgeGraph/GraphTraversal application-layer infrastructure.

Architecture note: Application layer. Zero domain imports beyond
reading entity IDs, keys, and enum values off already-constructed
domain objects — no business logic lives here, only projection.
Stateless; only calls KnowledgeGraph.add_node()/add_edge().
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.application.knowledge_graph import (
    GraphEdge,
    GraphNode,
    KnowledgeGraph,
    NodeType,
    RelationshipType,
)

if TYPE_CHECKING:
    from redforge.domain.attack_library.entity import AttackDefinition
    from redforge.domain.attack_library.taxonomy import AttackTaxonomyNode
    from redforge.domain.attack_library.value_objects import AttackRelationshipType

_RELATIONSHIP_TYPE_MAP: dict[AttackRelationshipType, RelationshipType] = {}


def _relationship_type_map() -> dict[AttackRelationshipType, RelationshipType]:
    """Lazily built mapping from the domain's AttackRelationshipType to
    the graph's RelationshipType. Built once, from data (enum values),
    not a hardcoded if/elif chain — every AttackRelationshipType member
    is required to have a corresponding graph RelationshipType, or this
    raises at first use rather than silently dropping an edge."""
    if not _RELATIONSHIP_TYPE_MAP:
        from redforge.domain.attack_library.value_objects import AttackRelationshipType

        _RELATIONSHIP_TYPE_MAP.update({
            AttackRelationshipType.PARENT_OF: RelationshipType.ATTACK_PARENT_OF,
            AttackRelationshipType.DERIVED_FROM: RelationshipType.ATTACK_DERIVED_FROM,
            AttackRelationshipType.PREREQUISITE_OF: RelationshipType.ATTACK_PREREQUISITE_OF,
            AttackRelationshipType.COMPOSED_OF: RelationshipType.ATTACK_COMPOSED_OF,
        })
    return _RELATIONSHIP_TYPE_MAP


class AttackKnowledgeGraphProjector:
    """Projects Attack Taxonomy nodes and Attack Definition relationships
    into the shared Knowledge Graph, enabling generic BFS/shortest-path/
    ancestor-descendant traversal over them via GraphTraversal — without
    the attack_library bounded context needing its own graph engine."""

    def __init__(self, graph: KnowledgeGraph) -> None:
        self._graph = graph

    def project_taxonomy_node(self, node: AttackTaxonomyNode) -> None:
        """Add a taxonomy node, and its edge to its parent (if any)."""
        self._graph.add_node(GraphNode(
            node_id=str(node.id),
            node_type=NodeType.ATTACK_TAXONOMY_NODE,
            label=node.name,
            metadata={"key": str(node.key), "is_active": str(node.is_active)},
        ))
        if node.parent_id is not None:
            self._graph.add_edge(GraphEdge(
                source_id=str(node.parent_id),
                target_id=str(node.id),
                relationship=RelationshipType.TAXONOMY_PARENT_OF,
            ))

    def project_attack(self, attack: AttackDefinition) -> None:
        """Add an attack definition node, its classification edge (if
        classified under a taxonomy node), and every declared
        relationship edge to other attacks."""
        self._graph.add_node(GraphNode(
            node_id=str(attack.id),
            node_type=NodeType.ATTACK_DEFINITION,
            label=attack.display_name,
            metadata={
                "category": str(attack.category),
                "severity": str(attack.severity),
                "status": str(attack.status),
            },
        ))
        if attack.taxonomy_node_id is not None:
            self._graph.add_edge(GraphEdge(
                source_id=str(attack.id),
                target_id=str(attack.taxonomy_node_id),
                relationship=RelationshipType.ATTACK_CLASSIFIED_UNDER,
            ))
        relationship_types = _relationship_type_map()
        for relationship in attack.relationships:
            self._graph.add_edge(GraphEdge(
                source_id=str(attack.id),
                target_id=str(relationship.related_attack_id),
                relationship=relationship_types[relationship.relationship_type],
                metadata={"notes": relationship.notes} if relationship.notes else {},
            ))
