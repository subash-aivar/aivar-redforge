"""Unit tests for AttackKnowledgeGraphProjector — verifies the Attack
Taxonomy tree and Attack Relationship graph are projected correctly
into the shared KnowledgeGraph, and that the resulting graph supports
real traversal (BFS, shortest-path, ancestors) per the "Support graph
traversal" requirement — using the platform's existing graph engine,
not a new one.
"""

from __future__ import annotations

from redforge.application.attack_knowledge_projector import AttackKnowledgeGraphProjector
from redforge.application.knowledge_graph import (
    GraphNode,
    KnowledgeGraph,
    NodeType,
    RelationshipType,
)
from redforge.domain.attack_library.entity import AttackDefinition
from redforge.domain.attack_library.taxonomy import AttackTaxonomyNode
from redforge.domain.attack_library.value_objects import (
    AttackCategory,
    AttackRelationshipType,
    AttackSeverity,
    AttackTechnique,
)
from redforge.shared.identifiers import EntityId


def _stub_node(graph: KnowledgeGraph, node_id: EntityId, node_type: NodeType) -> None:
    """Add a bare placeholder node — the graph store enforces
    referential integrity (an edge's endpoints must already exist), so
    tests exercising a relationship edge to a related entity need that
    entity present in the graph first, exactly as a real caller would
    project the related attack/taxonomy node before (or as part of)
    projecting the edge that references it."""
    graph.add_node(GraphNode(node_id=str(node_id), node_type=node_type, label="stub"))


def _attack(name: str = "direct-injection") -> AttackDefinition:
    return AttackDefinition.create(
        name=name, display_name=name.title(), description="...",
        category=AttackCategory.PROMPT_INJECTION,
        technique=AttackTechnique(technique="Prompt Injection"),
        severity=AttackSeverity.HIGH,
    )


class TestProjectTaxonomyNode:
    def test_adds_node(self) -> None:
        graph = KnowledgeGraph()
        node = AttackTaxonomyNode.create(
            key="prompt_injection", name="Prompt Injection", description="...",
        )
        AttackKnowledgeGraphProjector(graph).project_taxonomy_node(node)
        found = graph.query_by_type(NodeType.ATTACK_TAXONOMY_NODE)
        assert len(found) == 1
        assert found[0].node_id == str(node.id)

    def test_root_node_has_no_parent_edge(self) -> None:
        graph = KnowledgeGraph()
        node = AttackTaxonomyNode.create(key="a", name="Root", description="...")
        AttackKnowledgeGraphProjector(graph).project_taxonomy_node(node)
        assert graph.query_by_relationship(RelationshipType.TAXONOMY_PARENT_OF) == []

    def test_child_node_gets_parent_edge(self) -> None:
        graph = KnowledgeGraph()
        parent = AttackTaxonomyNode.create(key="a", name="Root", description="...")
        child = AttackTaxonomyNode.create(
            key="b", name="Child", description="...", parent_id=parent.id,
        )
        projector = AttackKnowledgeGraphProjector(graph)
        projector.project_taxonomy_node(parent)
        projector.project_taxonomy_node(child)
        edges = graph.query_by_relationship(RelationshipType.TAXONOMY_PARENT_OF)
        assert len(edges) == 1
        assert edges[0].source_id == str(parent.id)
        assert edges[0].target_id == str(child.id)

    def test_deep_tree_is_traversable_by_bfs(self) -> None:
        """The graph traversal requirement, demonstrated: a 3-level
        taxonomy chain must be fully reachable from the root via BFS —
        proving projection didn't just add isolated nodes."""
        graph = KnowledgeGraph()
        projector = AttackKnowledgeGraphProjector(graph)
        root = AttackTaxonomyNode.create(key="root", name="Root", description="...")
        mid = AttackTaxonomyNode.create(
            key="mid", name="Mid", description="...", parent_id=root.id,
        )
        leaf = AttackTaxonomyNode.create(
            key="leaf", name="Leaf", description="...", parent_id=mid.id,
        )
        for node in (root, mid, leaf):
            projector.project_taxonomy_node(node)

        result = graph.query_related(str(root.id), max_depth=5)
        node_ids = {n.node_id for n in result.nodes}
        assert str(mid.id) in node_ids
        assert str(leaf.id) in node_ids

        path = graph.query_shortest_path(str(root.id), str(leaf.id))
        assert path == [str(root.id), str(mid.id), str(leaf.id)]


class TestProjectAttack:
    def test_adds_attack_node(self) -> None:
        graph = KnowledgeGraph()
        attack = _attack()
        AttackKnowledgeGraphProjector(graph).project_attack(attack)
        found = graph.query_by_type(NodeType.ATTACK_DEFINITION)
        assert len(found) == 1
        assert found[0].node_id == str(attack.id)

    def test_unclassified_attack_has_no_classification_edge(self) -> None:
        graph = KnowledgeGraph()
        AttackKnowledgeGraphProjector(graph).project_attack(_attack())
        assert graph.query_by_relationship(RelationshipType.ATTACK_CLASSIFIED_UNDER) == []

    def test_classified_attack_gets_classification_edge(self) -> None:
        graph = KnowledgeGraph()
        attack = _attack()
        node_id = EntityId.generate()
        attack.classify_under(node_id)
        _stub_node(graph, node_id, NodeType.ATTACK_TAXONOMY_NODE)
        AttackKnowledgeGraphProjector(graph).project_attack(attack)
        edges = graph.query_by_relationship(RelationshipType.ATTACK_CLASSIFIED_UNDER)
        assert len(edges) == 1
        assert edges[0].source_id == str(attack.id)
        assert edges[0].target_id == str(node_id)

    def test_every_relationship_type_maps_to_a_graph_edge(self) -> None:
        """Every AttackRelationshipType member must project to a real
        graph edge — a silently-dropped relationship type would be a
        correctness bug in the enterprise knowledge model."""
        graph = KnowledgeGraph()
        attack = _attack("composed-attack")
        related_ids = {rel_type: EntityId.generate() for rel_type in AttackRelationshipType}
        for rel_type, related_id in related_ids.items():
            attack.relate_to(related_id, rel_type)
            _stub_node(graph, related_id, NodeType.ATTACK_DEFINITION)

        AttackKnowledgeGraphProjector(graph).project_attack(attack)

        expected_graph_types = {
            RelationshipType.ATTACK_PARENT_OF,
            RelationshipType.ATTACK_DERIVED_FROM,
            RelationshipType.ATTACK_PREREQUISITE_OF,
            RelationshipType.ATTACK_COMPOSED_OF,
        }
        found_types = {
            e.relationship for t in expected_graph_types
            for e in graph.query_by_relationship(t)
        }
        assert found_types == expected_graph_types
        assert len(related_ids) == len(AttackRelationshipType)

    def test_relationship_targets_are_correct_nodes(self) -> None:
        graph = KnowledgeGraph()
        attack = _attack("parent-child")
        parent_technique_id = EntityId.generate()
        attack.relate_to(parent_technique_id, AttackRelationshipType.PARENT_OF)
        _stub_node(graph, parent_technique_id, NodeType.ATTACK_DEFINITION)

        AttackKnowledgeGraphProjector(graph).project_attack(attack)

        edges = graph.query_by_relationship(RelationshipType.ATTACK_PARENT_OF)
        assert len(edges) == 1
        assert edges[0].source_id == str(attack.id)
        assert edges[0].target_id == str(parent_technique_id)

    def test_relationship_notes_carried_into_edge_metadata(self) -> None:
        graph = KnowledgeGraph()
        attack = _attack("noted-attack")
        other_id = EntityId.generate()
        attack.relate_to(other_id, AttackRelationshipType.DERIVED_FROM, notes="via CVE-2024-xxxx")
        _stub_node(graph, other_id, NodeType.ATTACK_DEFINITION)

        AttackKnowledgeGraphProjector(graph).project_attack(attack)

        edges = graph.query_by_relationship(RelationshipType.ATTACK_DERIVED_FROM)
        assert edges[0].metadata.get("notes") == "via CVE-2024-xxxx"


class TestFullKnowledgeModelTraversal:
    def test_attack_to_taxonomy_to_related_attack_is_traversable(self) -> None:
        """End-to-end: an attack classified under a taxonomy node, with
        a relationship to a second attack, is fully connected in the
        graph — the shape the Enterprise AI Attack Knowledge Model
        needs future campaign/runtime/autonomous-agent workflows to
        query against."""
        graph = KnowledgeGraph()
        projector = AttackKnowledgeGraphProjector(graph)

        taxonomy_root = AttackTaxonomyNode.create(
            key="prompt_injection", name="Prompt Injection", description="...",
        )
        projector.project_taxonomy_node(taxonomy_root)

        base_attack = _attack("base-injection")
        base_attack.classify_under(taxonomy_root.id)
        projector.project_attack(base_attack)

        derived_attack = _attack("derived-injection")
        derived_attack.classify_under(taxonomy_root.id)
        derived_attack.relate_to(base_attack.id, AttackRelationshipType.DERIVED_FROM)
        projector.project_attack(derived_attack)

        result = graph.query_related(str(derived_attack.id), max_depth=3)
        reachable_ids = {n.node_id for n in result.nodes}
        assert str(base_attack.id) in reachable_ids
        assert str(taxonomy_root.id) in reachable_ids
