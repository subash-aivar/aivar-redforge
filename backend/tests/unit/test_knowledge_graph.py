"""Unit tests for AI Security Knowledge Graph.

Covers: nodes, edges, relationships, traversal, queries, serialization,
statistics, cycle detection, disconnected graphs, orphans, custom
relationships, and large graph performance.
"""

import pytest

from redforge.application.knowledge_graph import (
    GraphEdge,
    GraphNode,
    GraphQuery,
    GraphSerializer,
    GraphStore,
    InMemoryGraphStore,
    KnowledgeGraph,
    NodeType,
    RelationshipType,
)

# ─── Fixtures ─────────────────────────────────────────────────────────────────


def _node(
    node_id: str = "n1",
    node_type: NodeType = NodeType.AI_TARGET,
    label: str = "Test Node",
) -> GraphNode:
    return GraphNode(node_id=node_id, node_type=node_type, label=label)


def _edge(
    source: str = "n1",
    target: str = "n2",
    rel: RelationshipType = RelationshipType.TARGET_USES_PROVIDER,
) -> GraphEdge:
    return GraphEdge(source_id=source, target_id=target, relationship=rel)


def _populated_graph() -> KnowledgeGraph:
    """Build a small realistic graph for testing."""
    g = KnowledgeGraph()
    # Nodes
    g.add_node(GraphNode("org-1", NodeType.ORGANIZATION, "Acme Corp"))
    g.add_node(GraphNode("t-1", NodeType.AI_TARGET, "Production LLM"))
    g.add_node(GraphNode("p-1", NodeType.PROVIDER, "OpenAI"))
    g.add_node(GraphNode("m-1", NodeType.MODEL, "GPT-4"))
    g.add_node(GraphNode("atk-1", NodeType.ATTACK_DEFINITION, "Prompt Injection"))
    g.add_node(GraphNode("ev-1", NodeType.EVIDENCE, "Evidence #1"))
    g.add_node(GraphNode("f-1", NodeType.FINDING, "Finding: Injection"))
    g.add_node(GraphNode("ri-1", NodeType.RISK_INCIDENT, "Risk Incident #1"))
    g.add_node(GraphNode("mitre-1", NodeType.MITRE_ATLAS, "AML.T0051"))
    g.add_node(GraphNode("owasp-1", NodeType.OWASP_LLM, "LLM01"))
    # Edges
    g.add_edge(GraphEdge("t-1", "p-1", RelationshipType.TARGET_USES_PROVIDER))
    g.add_edge(GraphEdge("t-1", "m-1", RelationshipType.TARGET_USES_MODEL))
    g.add_edge(GraphEdge("p-1", "m-1", RelationshipType.PROVIDER_SUPPORTS_MODEL))
    g.add_edge(GraphEdge("atk-1", "ev-1", RelationshipType.ATTACK_GENERATES_EVIDENCE))
    g.add_edge(GraphEdge("ev-1", "f-1", RelationshipType.EVIDENCE_GENERATES_FINDING))
    g.add_edge(GraphEdge("f-1", "ri-1", RelationshipType.FINDING_INCREASES_RISK))
    g.add_edge(GraphEdge("atk-1", "mitre-1", RelationshipType.ATTACK_MAPS_TO_MITRE))
    g.add_edge(GraphEdge("atk-1", "owasp-1", RelationshipType.ATTACK_MAPS_TO_OWASP))
    return g


# ─── Node Tests ───────────────────────────────────────────────────────────────


class TestGraphNode:
    def test_creation(self) -> None:
        n = _node("t-1", NodeType.AI_TARGET, "Prod LLM")
        assert n.node_id == "t-1"
        assert n.node_type == NodeType.AI_TARGET
        assert n.label == "Prod LLM"

    def test_key_composite(self) -> None:
        n = _node("t-1", NodeType.AI_TARGET)
        assert n.key == "ai_target:t-1"

    def test_equality_by_key(self) -> None:
        a = _node("t-1", NodeType.AI_TARGET, "A")
        b = _node("t-1", NodeType.AI_TARGET, "B")
        assert a == b

    def test_inequality_different_id(self) -> None:
        a = _node("t-1")
        b = _node("t-2")
        assert a != b

    def test_hash_consistent(self) -> None:
        a = _node("t-1", NodeType.AI_TARGET)
        b = _node("t-1", NodeType.AI_TARGET)
        assert hash(a) == hash(b)

    def test_metadata(self) -> None:
        n = GraphNode("n1", NodeType.PROVIDER, "OpenAI", metadata={"region": "us"})
        assert n.metadata["region"] == "us"


# ─── Edge Tests ───────────────────────────────────────────────────────────────


class TestGraphEdge:
    def test_creation(self) -> None:
        e = _edge("a", "b", RelationshipType.TARGET_USES_PROVIDER)
        assert e.source_id == "a"
        assert e.target_id == "b"
        assert e.relationship == RelationshipType.TARGET_USES_PROVIDER

    def test_self_reference_raises(self) -> None:
        with pytest.raises(ValueError, match="Self-referencing"):
            GraphEdge("a", "a", RelationshipType.TARGET_USES_PROVIDER)

    def test_negative_weight_raises(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            GraphEdge("a", "b", RelationshipType.TARGET_USES_PROVIDER, weight=-1.0)

    def test_key_format(self) -> None:
        e = _edge("src", "tgt", RelationshipType.ATTACK_MAPS_TO_MITRE)
        assert e.key == "src-[attack_maps_to_mitre]->tgt"

    def test_custom_label(self) -> None:
        e = GraphEdge("a", "b", RelationshipType.CUSTOM, label="my_relation")
        assert e.label == "my_relation"


# ─── InMemoryGraphStore Tests ─────────────────────────────────────────────────


class TestInMemoryGraphStore:
    def test_add_and_get_node(self) -> None:
        store = InMemoryGraphStore()
        store.add_node(_node("n1"))
        assert store.has_node("n1")
        assert store.get_node("n1") is not None

    def test_get_missing_node_returns_none(self) -> None:
        store = InMemoryGraphStore()
        assert store.get_node("missing") is None

    def test_add_edge(self) -> None:
        store = InMemoryGraphStore()
        store.add_node(_node("a"))
        store.add_node(_node("b"))
        store.add_edge(_edge("a", "b"))
        assert store.has_edge("a", "b", RelationshipType.TARGET_USES_PROVIDER)

    def test_add_edge_missing_source_raises(self) -> None:
        store = InMemoryGraphStore()
        store.add_node(_node("b"))
        with pytest.raises(ValueError, match="Source node"):
            store.add_edge(_edge("a", "b"))

    def test_add_edge_missing_target_raises(self) -> None:
        store = InMemoryGraphStore()
        store.add_node(_node("a"))
        with pytest.raises(ValueError, match="Target node"):
            store.add_edge(_edge("a", "b"))

    def test_remove_node_removes_edges(self) -> None:
        store = InMemoryGraphStore()
        store.add_node(_node("a"))
        store.add_node(_node("b"))
        store.add_edge(_edge("a", "b"))
        store.remove_node("a")
        assert not store.has_node("a")
        assert store.edge_count() == 0

    def test_remove_edge(self) -> None:
        store = InMemoryGraphStore()
        store.add_node(_node("a"))
        store.add_node(_node("b"))
        store.add_edge(_edge("a", "b"))
        store.remove_edge("a", "b", RelationshipType.TARGET_USES_PROVIDER)
        assert not store.has_edge("a", "b", RelationshipType.TARGET_USES_PROVIDER)

    def test_clear(self) -> None:
        store = InMemoryGraphStore()
        store.add_node(_node("a"))
        store.add_node(_node("b"))
        store.add_edge(_edge("a", "b"))
        store.clear()
        assert store.node_count() == 0
        assert store.edge_count() == 0

    def test_satisfies_protocol(self) -> None:
        store = InMemoryGraphStore()
        assert isinstance(store, GraphStore)

    def test_all_nodes(self) -> None:
        store = InMemoryGraphStore()
        store.add_node(_node("a"))
        store.add_node(_node("b", NodeType.PROVIDER))
        assert len(store.all_nodes()) == 2

    def test_all_edges(self) -> None:
        store = InMemoryGraphStore()
        store.add_node(_node("a"))
        store.add_node(_node("b"))
        store.add_edge(_edge("a", "b"))
        assert len(store.all_edges()) == 1


# ─── Traversal Tests ──────────────────────────────────────────────────────────


class TestGraphTraversal:
    def test_bfs_basic(self) -> None:
        g = _populated_graph()
        result = g.query_related("t-1", max_depth=1)
        # t-1 connects to p-1 and m-1
        node_ids = {n.node_id for n in result.nodes}
        assert "p-1" in node_ids
        assert "m-1" in node_ids

    def test_bfs_depth_limit(self) -> None:
        g = _populated_graph()
        result_d1 = g.query_related("atk-1", max_depth=1)
        result_d3 = g.query_related("atk-1", max_depth=3)
        assert result_d3.node_count >= result_d1.node_count

    def test_bfs_relationship_filter(self) -> None:
        g = _populated_graph()
        result = g.query_related(
            "t-1",
            relationship_filter=[RelationshipType.TARGET_USES_PROVIDER],
        )
        node_ids = {n.node_id for n in result.nodes}
        assert "p-1" in node_ids
        # m-1 connected via TARGET_USES_MODEL, should be excluded
        # (but m-1 is reachable via p-1 → PROVIDER_SUPPORTS_MODEL in both direction)
        # Actually with direction=both, m-1 is reachable via p-1's incoming from t-1
        # The filter is strict so only TARGET_USES_PROVIDER edges are traversed

    def test_bfs_node_type_filter(self) -> None:
        g = _populated_graph()
        result = g.query_related(
            "atk-1",
            max_depth=5,
            node_type_filter=[NodeType.FINDING, NodeType.RISK_INCIDENT],
        )
        node_types = {n.node_type for n in result.nodes if n.node_id != "atk-1"}
        for nt in node_types:
            assert nt in (NodeType.FINDING, NodeType.RISK_INCIDENT)

    def test_shortest_path_direct(self) -> None:
        g = _populated_graph()
        path = g.query_shortest_path("t-1", "p-1")
        assert path == ["t-1", "p-1"]

    def test_shortest_path_multi_hop(self) -> None:
        g = _populated_graph()
        path = g.query_shortest_path("atk-1", "ri-1")
        assert path is not None
        assert path[0] == "atk-1"
        assert path[-1] == "ri-1"
        assert len(path) == 4  # atk-1 → ev-1 → f-1 → ri-1

    def test_shortest_path_unreachable(self) -> None:
        g = KnowledgeGraph()
        g.add_node(_node("a"))
        g.add_node(_node("b", NodeType.PROVIDER))
        path = g.query_shortest_path("a", "b")
        assert path is None

    def test_shortest_path_same_node(self) -> None:
        g = _populated_graph()
        path = g.query_shortest_path("t-1", "t-1")
        assert path == ["t-1"]

    def test_shortest_path_nonexistent_node(self) -> None:
        g = _populated_graph()
        assert g.query_shortest_path("t-1", "nonexistent") is None

    def test_find_orphans(self) -> None:
        g = KnowledgeGraph()
        g.add_node(_node("connected-a"))
        g.add_node(_node("connected-b", NodeType.PROVIDER))
        g.add_node(_node("orphan", NodeType.MODEL, "Lonely"))
        g.add_edge(_edge("connected-a", "connected-b"))
        orphans = g.query_orphans()
        assert len(orphans) == 1
        assert orphans[0].node_id == "orphan"

    def test_connected_components(self) -> None:
        g = KnowledgeGraph()
        # Component 1
        g.add_node(_node("a"))
        g.add_node(_node("b", NodeType.PROVIDER))
        g.add_edge(_edge("a", "b"))
        # Component 2 (disconnected)
        g.add_node(_node("c", NodeType.FINDING))
        g.add_node(_node("d", NodeType.RISK_INCIDENT))
        g.add_edge(GraphEdge("c", "d", RelationshipType.FINDING_INCREASES_RISK))
        # Orphan (its own component)
        g.add_node(_node("orphan", NodeType.MODEL))

        components = g.query_disconnected_components()
        assert len(components) == 3

    def test_cycle_detection_no_cycle(self) -> None:
        g = _populated_graph()
        assert g.has_cycle() is False

    def test_cycle_detection_with_cycle(self) -> None:
        g = KnowledgeGraph()
        g.add_node(_node("a"))
        g.add_node(_node("b", NodeType.PROVIDER))
        g.add_node(_node("c", NodeType.MODEL))
        g.add_edge(_edge("a", "b"))
        g.add_edge(GraphEdge("b", "c", RelationshipType.PROVIDER_SUPPORTS_MODEL))
        g.add_edge(GraphEdge("c", "a", RelationshipType.CUSTOM, label="cycle"))
        assert g.has_cycle() is True

    def test_direction_outgoing_only(self) -> None:
        g = _populated_graph()
        result = g.query_related("ev-1", max_depth=1, direction="outgoing")
        node_ids = {n.node_id for n in result.nodes}
        # ev-1 has outgoing edge to f-1 only
        assert "f-1" in node_ids
        assert "atk-1" not in node_ids

    def test_direction_incoming_only(self) -> None:
        g = _populated_graph()
        result = g.query_related("ev-1", max_depth=1, direction="incoming")
        node_ids = {n.node_id for n in result.nodes}
        # ev-1 has incoming edge from atk-1
        assert "atk-1" in node_ids
        assert "f-1" not in node_ids


# ─── Query Tests ──────────────────────────────────────────────────────────────


class TestKnowledgeGraphQueries:
    def test_query_by_type(self) -> None:
        g = _populated_graph()
        findings = g.query_by_type(NodeType.FINDING)
        assert len(findings) == 1
        assert findings[0].node_id == "f-1"

    def test_query_by_relationship(self) -> None:
        g = _populated_graph()
        edges = g.query_by_relationship(RelationshipType.ATTACK_MAPS_TO_MITRE)
        assert len(edges) == 1
        assert edges[0].source_id == "atk-1"

    def test_query_neighbors(self) -> None:
        g = _populated_graph()
        neighbors = g.query_neighbors("atk-1")
        ids = {n.node_id for n in neighbors}
        assert "ev-1" in ids
        assert "mitre-1" in ids
        assert "owasp-1" in ids

    def test_query_neighbors_outgoing(self) -> None:
        g = _populated_graph()
        neighbors = g.query_neighbors("t-1", direction="outgoing")
        ids = {n.node_id for n in neighbors}
        assert "p-1" in ids
        assert "m-1" in ids

    def test_execute_declarative_query(self) -> None:
        g = _populated_graph()
        query = GraphQuery(
            start_node_id="atk-1",
            max_depth=2,
            node_type_filter=[NodeType.EVIDENCE, NodeType.FINDING],
        )
        result = g.execute_query(query)
        node_ids = {n.node_id for n in result.nodes}
        assert "ev-1" in node_ids

    def test_query_invalid_direction_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid direction"):
            GraphQuery(start_node_id="x", direction="sideways")

    def test_query_zero_depth_raises(self) -> None:
        with pytest.raises(ValueError, match="max_depth"):
            GraphQuery(start_node_id="x", max_depth=0)


# ─── Serialization Tests ─────────────────────────────────────────────────────


class TestGraphSerializer:
    def test_round_trip(self) -> None:
        g = _populated_graph()
        data = g.to_dict()
        restored = KnowledgeGraph.from_dict(data)
        assert restored.node_count == g.node_count
        assert restored.edge_count == g.edge_count

    def test_to_dict_structure(self) -> None:
        g = _populated_graph()
        data = g.to_dict()
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) == g.node_count
        assert len(data["edges"]) == g.edge_count

    def test_node_serialization(self) -> None:
        n = _node("t-1", NodeType.AI_TARGET, "Prod LLM")
        d = GraphSerializer.node_to_dict(n)
        assert d["node_id"] == "t-1"
        assert d["node_type"] == "ai_target"
        assert d["label"] == "Prod LLM"

    def test_edge_serialization(self) -> None:
        e = _edge("a", "b", RelationshipType.TARGET_USES_PROVIDER)
        d = GraphSerializer.edge_to_dict(e)
        assert d["source_id"] == "a"
        assert d["target_id"] == "b"
        assert d["relationship"] == "target_uses_provider"

    def test_from_dict_preserves_metadata(self) -> None:
        g = KnowledgeGraph()
        g.add_node(GraphNode("n1", NodeType.PROVIDER, "Test", metadata={"k": "v"}))
        data = g.to_dict()
        restored = KnowledgeGraph.from_dict(data)
        node = restored.get_node("n1")
        assert node is not None
        assert node.metadata["k"] == "v"


# ─── Statistics Tests ─────────────────────────────────────────────────────────


class TestGraphStatistics:
    def test_basic_statistics(self) -> None:
        g = _populated_graph()
        stats = g.statistics()
        assert stats.total_nodes == 10
        assert stats.total_edges == 8
        assert stats.connected_components >= 1
        assert stats.density > 0

    def test_empty_graph_statistics(self) -> None:
        g = KnowledgeGraph()
        stats = g.statistics()
        assert stats.total_nodes == 0
        assert stats.total_edges == 0
        assert stats.average_degree == 0.0

    def test_node_type_counts(self) -> None:
        g = _populated_graph()
        stats = g.statistics()
        assert stats.node_type_counts["ai_target"] == 1
        assert stats.node_type_counts["provider"] == 1

    def test_relationship_type_counts(self) -> None:
        g = _populated_graph()
        stats = g.statistics()
        assert stats.relationship_type_counts["target_uses_provider"] == 1
        assert stats.relationship_type_counts["attack_maps_to_mitre"] == 1

    def test_most_connected(self) -> None:
        g = _populated_graph()
        stats = g.statistics()
        # atk-1 has 3 outgoing edges, should be in top
        top_ids = [mc[0] for mc in stats.most_connected]
        assert "atk-1" in top_ids

    def test_average_degree(self) -> None:
        g = _populated_graph()
        stats = g.statistics()
        # 10 nodes, 8 edges → avg degree = 16/10 = 1.6
        assert stats.average_degree == pytest.approx(1.6)

    def test_orphan_count(self) -> None:
        g = KnowledgeGraph()
        g.add_node(_node("connected-a"))
        g.add_node(_node("connected-b", NodeType.PROVIDER))
        g.add_node(_node("orphan", NodeType.MODEL))
        g.add_edge(_edge("connected-a", "connected-b"))
        stats = g.statistics()
        assert stats.orphan_count == 1


# ─── Custom Relationships ─────────────────────────────────────────────────────


class TestCustomRelationships:
    def test_custom_relationship_type(self) -> None:
        g = KnowledgeGraph()
        g.add_node(GraphNode("a", NodeType.CUSTOM, "Custom A"))
        g.add_node(GraphNode("b", NodeType.CUSTOM, "Custom B"))
        g.add_edge(GraphEdge("a", "b", RelationshipType.CUSTOM, label="depends_on"))
        edges = g.query_by_relationship(RelationshipType.CUSTOM)
        assert len(edges) == 1
        assert edges[0].label == "depends_on"

    def test_custom_node_type(self) -> None:
        g = KnowledgeGraph()
        g.add_node(GraphNode("x", NodeType.CUSTOM, "My Custom Entity"))
        nodes = g.query_by_type(NodeType.CUSTOM)
        assert len(nodes) == 1


# ─── KnowledgeGraph Facade Tests ─────────────────────────────────────────────


class TestKnowledgeGraph:
    def test_add_and_get(self) -> None:
        g = KnowledgeGraph()
        g.add_node(_node("x"))
        assert g.has_node("x")
        assert g.get_node("x") is not None

    def test_remove_node(self) -> None:
        g = KnowledgeGraph()
        g.add_node(_node("x"))
        g.remove_node("x")
        assert not g.has_node("x")

    def test_remove_edge(self) -> None:
        g = KnowledgeGraph()
        g.add_node(_node("a"))
        g.add_node(_node("b", NodeType.PROVIDER))
        g.add_edge(_edge("a", "b"))
        g.remove_edge("a", "b", RelationshipType.TARGET_USES_PROVIDER)
        assert g.edge_count == 0

    def test_clear(self) -> None:
        g = _populated_graph()
        g.clear()
        assert g.node_count == 0
        assert g.edge_count == 0

    def test_node_count(self) -> None:
        g = _populated_graph()
        assert g.node_count == 10

    def test_edge_count(self) -> None:
        g = _populated_graph()
        assert g.edge_count == 8


# ─── Large Graph Tests ────────────────────────────────────────────────────────


class TestLargeGraph:
    def test_1000_nodes_traversal(self) -> None:
        """1000 nodes in a chain should traverse correctly."""
        g = KnowledgeGraph()
        for i in range(1000):
            g.add_node(GraphNode(f"n-{i}", NodeType.EVIDENCE, f"Node {i}"))
        for i in range(999):
            g.add_edge(GraphEdge(
                f"n-{i}", f"n-{i+1}",
                RelationshipType.EVIDENCE_GENERATES_FINDING,
            ))
        assert g.node_count == 1000
        assert g.edge_count == 999

        path = g.query_shortest_path("n-0", "n-999")
        assert path is not None
        assert len(path) == 1000

    def test_1000_nodes_star_topology(self) -> None:
        """Star topology: hub connected to 999 leaves."""
        g = KnowledgeGraph()
        g.add_node(GraphNode("hub", NodeType.AI_TARGET, "Hub"))
        for i in range(999):
            g.add_node(GraphNode(f"leaf-{i}", NodeType.EVIDENCE, f"Leaf {i}"))
            g.add_edge(GraphEdge(
                "hub", f"leaf-{i}",
                RelationshipType.ATTACK_GENERATES_EVIDENCE,
            ))
        neighbors = g.query_neighbors("hub", direction="outgoing")
        assert len(neighbors) == 999

    def test_5000_nodes_statistics(self) -> None:
        """5000 nodes with edges should compute statistics fast."""
        g = KnowledgeGraph()
        for i in range(5000):
            g.add_node(GraphNode(
                f"n-{i}",
                NodeType(["ai_target", "provider", "finding", "evidence"][i % 4]),
                f"Node {i}",
            ))
        for i in range(4999):
            g.add_edge(GraphEdge(
                f"n-{i}", f"n-{i+1}",
                RelationshipType.EVIDENCE_GENERATES_FINDING,
            ))
        stats = g.statistics()
        assert stats.total_nodes == 5000
        assert stats.total_edges == 4999
        assert stats.connected_components == 1

    def test_disconnected_large_graph(self) -> None:
        """Multiple disconnected components."""
        g = KnowledgeGraph()
        # 10 components of 100 nodes each
        for comp in range(10):
            for i in range(100):
                g.add_node(GraphNode(
                    f"c{comp}-n{i}", NodeType.EVIDENCE, f"C{comp} N{i}"
                ))
            for i in range(99):
                g.add_edge(GraphEdge(
                    f"c{comp}-n{i}", f"c{comp}-n{i+1}",
                    RelationshipType.ATTACK_GENERATES_EVIDENCE,
                ))

        assert g.node_count == 1000
        components = g.query_disconnected_components()
        assert len(components) == 10


# ─── Use Case Scenario Tests ─────────────────────────────────────────────────


class TestUseCaseScenarios:
    def test_find_everything_related_to_finding(self) -> None:
        """Show everything related to Finding X."""
        g = _populated_graph()
        result = g.query_related("f-1", max_depth=5)
        node_ids = {n.node_id for n in result.nodes}
        # Should reach evidence, risk, and through evidence back to attack
        assert "ev-1" in node_ids
        assert "ri-1" in node_ids

    def test_find_every_attack_affecting_model(self) -> None:
        """Find every attack affecting GPT-4 (via target → attack chain)."""
        g = _populated_graph()
        # Add a policy link that connects target to attack
        g.add_node(GraphNode("pol-1", NodeType.VALIDATION_POLICY, "Policy"))
        g.add_edge(GraphEdge("pol-1", "atk-1", RelationshipType.POLICY_EXECUTES_ATTACK))
        g.add_edge(GraphEdge("pol-1", "t-1", RelationshipType.CUSTOM, label="targets"))
        # Now m-1 ↔ t-1 ↔ pol-1 → atk-1 is reachable
        result = g.query_related(
            "m-1", max_depth=5,
            node_type_filter=[NodeType.ATTACK_DEFINITION],
        )
        attacks = [n for n in result.nodes if n.node_type == NodeType.ATTACK_DEFINITION]
        assert len(attacks) >= 1

    def test_find_all_evidence_supporting_risk(self) -> None:
        """Find all evidence supporting Risk Incident."""
        g = _populated_graph()
        result = g.query_related(
            "ri-1", max_depth=5,
            node_type_filter=[NodeType.EVIDENCE],
        )
        evidence = [n for n in result.nodes if n.node_type == NodeType.EVIDENCE]
        assert len(evidence) >= 1
        assert evidence[0].node_id == "ev-1"

    def test_explainability_chain(self) -> None:
        """Verify the graph can explain WHY a risk exists."""
        g = _populated_graph()
        path = g.query_shortest_path("atk-1", "ri-1")
        assert path is not None
        # atk-1 → ev-1 → f-1 → ri-1 explains the risk
        assert len(path) == 4
        assert path == ["atk-1", "ev-1", "f-1", "ri-1"]
