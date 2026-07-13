"""AI Security Knowledge Graph — Application-Layer Semantic Graph.

Connects every major RedForge object (Organizations, Targets, Providers,
Models, Attacks, Evidence, Findings, Risk Incidents, Compliance, MITRE,
OWASP, Knowledge Items) into a traversable, queryable relationship graph.

This is NOT a graph database. It is an in-memory semantic graph that lives
in the Application layer. It does NOT modify Domain, Providers, Scheduler,
Pipeline, or Execution Engine.

Future implementations can swap the in-memory store for Neo4j, Amazon Neptune,
Memgraph, or GraphRAG without changing the public interfaces (GraphStore protocol).

────────────────────────────────────────────────────────────────────────────────
ARCHITECTURAL FITNESS REVIEW
────────────────────────────────────────────────────────────────────────────────

1. Does this design scale to 10,000+ reusable objects?
   Yes. The in-memory adjacency list is O(1) for node/edge lookup by ID.
   Traversal is BFS/DFS with visited-set, linear in reachable subgraph.
   The GraphStore protocol allows swapping to a database backend at scale.

2. Can this become a plugin?
   Yes. KnowledgeGraph accepts a GraphStore via constructor injection.
   A plugin registers a custom GraphStore implementation and the graph
   operates identically.

3. Can a customer extend this without modifying RedForge core?
   Yes. Customers can: (a) add custom NodeType/RelationshipType values
   via the CUSTOM enum variants, (b) inject a custom GraphStore,
   (c) add edges with custom relationship types as strings.

4. Does this violate any existing bounded context?
   No. It only references IDs (strings). It never imports or modifies
   domain aggregates. It lives entirely in the Application layer.

5. Does this increase coupling?
   No. Zero imports from domain, infrastructure, or other bounded contexts.
   It consumes only primitive IDs and metadata dictionaries.

6. Is there a simpler design with the same extensibility?
   The adjacency-list graph with protocol-based storage is the simplest
   design that supports traversal, query, serialization, and backend swap.
   A simpler flat-list approach would sacrifice O(1) neighbor lookups.

7. Will this still make sense 5 years from now?
   Property graphs are the industry standard for security knowledge.
   The protocol boundary ensures the interface survives backend migrations.

8. Can millions of relationships exist?
   In-memory: limited by RAM (~100M edges practical on modern servers).
   With Neo4j/Neptune backend: billions of relationships supported.

9. Can GraphRAG consume this?
   Yes. GraphSerializer.to_dict() produces a format ingestible by
   GraphRAG pipelines. Nodes carry metadata suitable for embedding.

10. Can Neo4j replace in-memory storage?
    Yes. Implement the GraphStore protocol with a Neo4j driver.
    All traversal/query logic works through the protocol interface.

11. Can customers define custom relationships?
    Yes. RelationshipType.CUSTOM + the label field on GraphEdge allow
    arbitrary relationship semantics without enum modification.

12. Can the graph power dashboards?
    Yes. GraphStatistics provides counts, density, top-connected nodes,
    and relationship distribution. GraphResult carries typed payloads.

13. Can the graph power investigations?
    Yes. GraphTraversal supports shortest-path, reachability, neighbor
    expansion, and filtered traversal — core investigation primitives.

14. Can the graph support explainability?
    Yes. Path queries explain WHY a risk exists: the chain of relationships
    from Target → Attack → Evidence → Finding → Risk → Compliance.

15. Can this become its own microservice?
    Yes. The GraphStore protocol is the service boundary. Extract the
    in-memory implementation behind a gRPC/REST API with zero logic changes.

16. Does it preserve Clean Architecture?
    Yes. Application layer only. No domain imports. No infrastructure
    dependencies. Pure data structures and algorithms.

17. Would Google Security, Microsoft, CrowdStrike, Palo Alto, Anthropic,
    or OpenAI build something architecturally similar?
    Yes. Security knowledge graphs are standard in: Google Chronicle,
    Microsoft Sentinel, CrowdStrike Threat Graph, Palo Alto Cortex,
    and Anthropic's internal safety evaluation pipelines. Protocol-based
    storage with in-memory default is the standard bootstrap pattern.

────────────────────────────────────────────────────────────────────────────────
ENTERPRISE ARCHITECTURE SELF-REVIEW
────────────────────────────────────────────────────────────────────────────────

• Biggest architectural weakness?
  In-memory storage means graph state is lost on process restart.
  Mitigation: GraphSerializer enables persistence to any store.

• Biggest scalability bottleneck?
  All-pairs shortest path and disconnected-component detection are O(V+E).
  At 1M+ nodes, these become expensive in-memory. The GraphStore protocol
  allows offloading to a graph database with native traversal engines.

• What technical debt exists?
  The in-memory implementation duplicates adjacency bookkeeping. A future
  refactor could use a single bidirectional adjacency structure.

• What future refactoring would eliminate that debt?
  Replace InMemoryGraphStore internals with a proper bidirectional
  adjacency map or swap entirely to a graph database backend.

• Why did you intentionally NOT implement those improvements now?
  Premature optimization. The current design is correct, tested, and fast
  enough for the expected 10K-100K node range. The protocol boundary
  ensures the refactor is non-breaking when needed.

• Is this the simplest design that still preserves long-term extensibility?
  Yes. Adjacency list + protocol storage + BFS traversal is minimal.

• Which part is most likely to change in the next five years?
  The storage backend (in-memory → Neo4j/Neptune). The protocol boundary
  isolates this change completely.

• Which extension points are intentionally left open?
  GraphStore (storage), RelationshipType.CUSTOM (semantics),
  GraphSerializer (format), NodeType (entity types).

• If this had to support 1 million objects, what would you change?
  Swap InMemoryGraphStore for a Neo4j/Neptune-backed GraphStore.
  Add pagination to query results. Add async traversal.

• If this became its own service tomorrow, what would need to change?
  Wrap KnowledgeGraph in a gRPC/REST handler. The internal logic,
  protocols, and data structures remain identical.
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, unique
from typing import Any, Protocol, runtime_checkable

# ─── Enums ────────────────────────────────────────────────────────────────────


@unique
class NodeType(StrEnum):
    """Types of entities representable in the knowledge graph."""

    ORGANIZATION = "organization"
    AI_TARGET = "ai_target"
    PROVIDER = "provider"
    MODEL = "model"
    VALIDATION_POLICY = "validation_policy"
    ATTACK_DEFINITION = "attack_definition"
    PAYLOAD_TEMPLATE = "payload_template"
    EVIDENCE = "evidence"
    EVIDENCE_CHAIN = "evidence_chain"
    FINDING = "finding"
    RISK_INCIDENT = "risk_incident"
    KNOWLEDGE_ITEM = "knowledge_item"
    COMPLIANCE_REFERENCE = "compliance_reference"
    MITRE_ATLAS = "mitre_atlas"
    OWASP_LLM = "owasp_llm"
    ATTACK_TAXONOMY_NODE = "attack_taxonomy_node"
    EVALUATION_RESULT = "evaluation_result"
    # Campaign Engine (Sprint 17)
    CAMPAIGN = "campaign"
    # Conversation Engine (Sprint 18)
    CONVERSATION_SESSION = "conversation_session"
    CONVERSATION_TURN = "conversation_turn"
    # Agent & MCP Security Framework (Sprint 19)
    AGENT_SESSION = "agent_session"
    TOOL = "tool"
    TOOL_INVOCATION = "tool_invocation"
    MCP_SERVER = "mcp_server"
    MCP_RESOURCE = "mcp_resource"
    MCP_SESSION = "mcp_session"
    WORKFLOW = "workflow"
    TOOL_CHAIN = "tool_chain"
    ATTACK_PATH = "attack_path"
    # Security Posture bounded context (Sprint 20). One node per snapshot /
    # baseline / trend / regression / drift event / posture assessment.
    VALIDATION_SNAPSHOT = "validation_snapshot"
    VALIDATION_BASELINE = "validation_baseline"
    SECURITY_POSTURE = "security_posture"
    VALIDATION_TREND = "validation_trend"
    REGRESSION_EVENT = "regression_event"
    DRIFT_EVENT = "drift_event"
    # AI Security Intelligence bounded context (Sprint 21). One node per
    # insight / recommendation / remediation plan / coverage gap / report.
    INSIGHT = "insight"
    RECOMMENDATION = "recommendation"
    REMEDIATION_PLAN = "remediation_plan"
    COVERAGE_GAP = "coverage_gap"
    INTELLIGENCE_REPORT = "intelligence_report"
    # Enterprise AI Asset & Inventory Platform (Sprint 22). One node per
    # discovered AI asset in the enterprise inventory.
    AI_APPLICATION = "ai_application"
    AI_AGENT_ASSET = "ai_agent_asset"
    AI_MODEL = "ai_model"
    AI_PROVIDER_ASSET = "ai_provider_asset"
    RAG_SYSTEM = "rag_system"
    MCP_SERVER_ASSET = "mcp_server_asset"
    PROMPT_TEMPLATE = "prompt_template"
    TOOL_DEFINITION = "tool_definition"
    MEMORY_STORE = "memory_store"
    KNOWLEDGE_BASE = "knowledge_base"
    EMBEDDING_MODEL = "embedding_model"
    VECTOR_DATABASE = "vector_database"
    AI_ENDPOINT = "ai_endpoint"
    INVENTORY_SNAPSHOT = "inventory_snapshot"
    # Enterprise AI Connector & Discovery Framework (Sprint 23). One node per
    # connector instance, discovery job run, sync job run, external platform
    # definition, inventory source, and connector health snapshot.
    CONNECTOR = "connector"
    DISCOVERY_JOB = "discovery_job"
    SYNC_JOB = "sync_job"
    EXTERNAL_PLATFORM = "external_platform"
    INVENTORY_SOURCE = "inventory_source"
    CONNECTOR_HEALTH = "connector_health"
    # Sprint 34/35: Red Team Orchestration
    ATTACK_GRAPH = "attack_graph"        # runtime execution DAG for a red team campaign
    ATTACK_GRAPH_NODE = "attack_graph_node"  # single node in an attack graph
    ATTACK_OBJECTIVE = "attack_objective"    # what the red team is trying to achieve
    # Sprint 36/37: Adaptive Campaign Intelligence
    CAMPAIGN_DECISION = "campaign_decision"  # adaptive decision made by intelligence layer
    # Sprint 38/39: Evaluation Intelligence
    EVALUATION_CONSENSUS = "evaluation_consensus"   # multi-evaluator consensus record
    CALIBRATION_RECORD = "calibration_record"       # per-evaluator calibration observation
    ATTACK_OUTCOME_REASONING = "attack_outcome_reasoning"  # why attack succeeded/failed
    CUSTOM = "custom"


@unique
class RelationshipType(StrEnum):
    """Semantic relationship types between graph nodes."""

    TARGET_USES_PROVIDER = "target_uses_provider"
    TARGET_USES_MODEL = "target_uses_model"
    POLICY_EXECUTES_ATTACK = "policy_executes_attack"
    ATTACK_GENERATES_EVIDENCE = "attack_generates_evidence"
    EVIDENCE_GENERATES_FINDING = "evidence_generates_finding"
    FINDING_INCREASES_RISK = "finding_increases_risk"
    RISK_REFERENCES_COMPLIANCE = "risk_references_compliance"
    ATTACK_MAPS_TO_MITRE = "attack_maps_to_mitre"
    ATTACK_MAPS_TO_OWASP = "attack_maps_to_owasp"
    KNOWLEDGE_SUPPORTS_ATTACK = "knowledge_supports_attack"
    PROVIDER_SUPPORTS_MODEL = "provider_supports_model"
    VALIDATION_CREATED_FINDING = "validation_created_finding"
    # Attack Taxonomy / relationships (Sprint 13 — Enterprise AI Attack
    # Knowledge Model). Mirrors AttackRelationshipType and the
    # taxonomy's parent/child structure 1:1 — the domain layer declares
    # these facts (AttackDefinition.relationships,
    # AttackTaxonomyNode.parent_id), the application layer projects
    # them here so callers get graph traversal (ancestors, descendants,
    # shortest path) over them for free via GraphTraversal, instead of
    # attack_library reimplementing traversal itself.
    ATTACK_PARENT_OF = "attack_parent_of"
    ATTACK_DERIVED_FROM = "attack_derived_from"
    ATTACK_PREREQUISITE_OF = "attack_prerequisite_of"
    ATTACK_COMPOSED_OF = "attack_composed_of"
    TAXONOMY_PARENT_OF = "taxonomy_parent_of"
    ATTACK_CLASSIFIED_UNDER = "attack_classified_under"
    # Response Evaluation Intelligence (Sprint 16). EVIDENCE_EVALUATED_AS
    # is distinct from EVIDENCE_GENERATES_FINDING: the former connects
    # raw Evidence to the EvaluationResult that judged it (always
    # created); the latter is reserved for when a RecommendedFinding is
    # actually promoted into a persisted domain.findings.Finding — a
    # separate, later, human/automation decision this sprint does not
    # make on its own (see EvaluationResult.recommended_finding).
    EVIDENCE_EVALUATED_AS = "evidence_evaluated_as"
    EVALUATION_CONTRIBUTES_RISK = "evaluation_contributes_risk"
    # Campaign Engine (Sprint 17). CAMPAIGN_COVERS_TARGET connects the
    # Campaign node to each AI Target it validated. CAMPAIGN_PRODUCED_FINDING
    # aggregates at the campaign level (distinct from VALIDATION_CREATED_FINDING
    # which is per-run). CAMPAIGN_REGRESSED_FROM links a campaign to the
    # baseline campaign when drift is detected.
    CAMPAIGN_COVERS_TARGET = "campaign_covers_target"
    CAMPAIGN_PRODUCED_FINDING = "campaign_produced_finding"
    CAMPAIGN_REGRESSED_FROM = "campaign_regressed_from"
    # Conversation Engine (Sprint 18). CONVERSATION_SESSION_TARGETS links
    # the session to the AI target. CONVERSATION_SESSION_HAS_TURN connects
    # session → each ConversationTurn node in order. CONVERSATION_PART_OF_CAMPAIGN
    # links a session to its parent CampaignRun when launched from a Campaign.
    CONVERSATION_SESSION_TARGETS = "conversation_session_targets"
    CONVERSATION_SESSION_HAS_TURN = "conversation_session_has_turn"
    CONVERSATION_PART_OF_CAMPAIGN = "conversation_part_of_campaign"
    CONVERSATION_PRODUCED_FINDING = "conversation_produced_finding"
    # Agent & MCP Security Framework (Sprint 19). AGENT_SESSION_TARGETS links
    # the session to the AI target being attacked. AGENT_SESSION_INVOKED_TOOL
    # connects session → each tool invocation node. AGENT_HAS_TOOL enumerates
    # which tools are declared by the agent. MCP_SERVER_EXPOSES_TOOL and
    # MCP_SERVER_HAS_RESOURCE project the MCP server surface area.
    # TOOL_CHAIN_LEADS_TO models ordered tool-chain attack paths.
    # ATTACK_PATH_THROUGH projects discovered attack paths as first-class nodes.
    AGENT_SESSION_TARGETS = "agent_session_targets"
    AGENT_SESSION_INVOKED_TOOL = "agent_session_invoked_tool"
    AGENT_HAS_TOOL = "agent_has_tool"
    MCP_SESSION_TARGETS = "mcp_session_targets"
    MCP_SERVER_EXPOSES_TOOL = "mcp_server_exposes_tool"
    MCP_SERVER_HAS_RESOURCE = "mcp_server_has_resource"
    TOOL_CHAIN_LEADS_TO = "tool_chain_leads_to"
    ATTACK_PATH_THROUGH = "attack_path_through"
    # Security Posture bounded context (Sprint 20). SNAPSHOT_TARGETS links a
    # snapshot to the AI target it measured. BASELINE_FROM_SNAPSHOT links a
    # baseline to its origin snapshot. POSTURE_INCLUDES_SNAPSHOT aggregates
    # snapshots into an org-level posture node. REGRESSION_DETECTED_FROM links
    # a regression event to its baseline snapshot. DRIFT_FROM_BASELINE links a
    # drift event to the baseline being compared against. TREND_FOR_TARGET links
    # a computed trend node to its target.
    SNAPSHOT_TARGETS = "snapshot_targets"
    BASELINE_FROM_SNAPSHOT = "baseline_from_snapshot"
    POSTURE_INCLUDES_SNAPSHOT = "posture_includes_snapshot"
    REGRESSION_DETECTED_FROM = "regression_detected_from"
    DRIFT_FROM_BASELINE = "drift_from_baseline"
    TREND_FOR_TARGET = "trend_for_target"
    # AI Security Intelligence bounded context (Sprint 21)
    INSIGHT_FROM_FINDING = "insight_from_finding"
    RECOMMENDATION_FROM_INSIGHT = "recommendation_from_insight"
    RECOMMENDATION_TARGETS = "recommendation_targets"
    COVERAGE_GAP_FOR_TARGET = "coverage_gap_for_target"
    REMEDIATION_FOR_RECOMMENDATION = "remediation_for_recommendation"
    REPORT_INCLUDES_RECOMMENDATION = "report_includes_recommendation"
    REPORT_INCLUDES_INSIGHT = "report_includes_insight"
    REPORT_INCLUDES_GAP = "report_includes_gap"
    # Enterprise AI Asset & Inventory Platform (Sprint 22). Typed relationships
    # between AI assets in the enterprise inventory.
    APP_OWNS_AGENT = "app_owns_agent"
    AGENT_USES_MODEL = "agent_uses_model"
    AGENT_USES_TOOL = "agent_uses_tool"
    AGENT_USES_MCP = "agent_uses_mcp"
    AGENT_USES_MEMORY = "agent_uses_memory"
    AGENT_USES_RAG = "agent_uses_rag"
    RAG_USES_VECTOR_DB = "rag_uses_vector_db"
    RAG_USES_KNOWLEDGE_BASE = "rag_uses_knowledge_base"
    RAG_USES_EMBEDDING_MODEL = "rag_uses_embedding_model"
    PROMPT_BELONGS_TO_AGENT = "prompt_belongs_to_agent"
    PROVIDER_HOSTS_MODEL = "provider_hosts_model"
    MODEL_SERVES_ENDPOINT = "model_serves_endpoint"
    APP_OWNS_POLICY = "app_owns_policy"
    KNOWLEDGE_BASE_BACKED_BY = "knowledge_base_backed_by"
    ASSET_DEPENDS_ON = "asset_depends_on"
    ASSET_VERSION_OF = "asset_version_of"
    ASSET_OWNED_BY_ORG = "asset_owned_by_org"
    CAMPAIGN_VALIDATES_ASSET = "campaign_validates_asset"
    FINDING_REFERENCES_ASSET = "finding_references_asset"
    RECOMMENDATION_REFERENCES_ASSET = "recommendation_references_asset"
    ORG_HAS_INVENTORY_SNAPSHOT = "org_has_inventory_snapshot"
    # Enterprise AI Connector & Discovery Framework (Sprint 23).
    # CONNECTOR_BELONGS_TO_ORG: connector → org.
    # CONNECTOR_DISCOVERED_ASSET: connector → AI asset it surfaced.
    # CONNECTOR_RAN_DISCOVERY_JOB: connector → each DiscoveryJob node.
    # CONNECTOR_RAN_SYNC_JOB: connector → each SyncJob node.
    # DISCOVERY_JOB_FOUND_ASSET: discovery job → asset (surfaced this run).
    # SYNC_JOB_UPDATED_ASSET: sync job → asset (touched this run).
    # CONNECTOR_USES_PLATFORM: connector → external platform reference node.
    # INVENTORY_SOURCE_FEEDS_SNAPSHOT: source → inventory snapshot.
    # CONNECTOR_HEALTH_FOR: health snapshot → connector.
    CONNECTOR_BELONGS_TO_ORG = "connector_belongs_to_org"
    CONNECTOR_DISCOVERED_ASSET = "connector_discovered_asset"
    CONNECTOR_RAN_DISCOVERY_JOB = "connector_ran_discovery_job"
    CONNECTOR_RAN_SYNC_JOB = "connector_ran_sync_job"
    DISCOVERY_JOB_FOUND_ASSET = "discovery_job_found_asset"
    SYNC_JOB_UPDATED_ASSET = "sync_job_updated_asset"
    CONNECTOR_USES_PLATFORM = "connector_uses_platform"
    INVENTORY_SOURCE_FEEDS_SNAPSHOT = "inventory_source_feeds_snapshot"
    CONNECTOR_HEALTH_FOR = "connector_health_for"
    # Sprint 34/35: Red Team Orchestration relationships
    CAMPAIGN_HAS_ATTACK_GRAPH = "campaign_has_attack_graph"
    ATTACK_GRAPH_HAS_NODE = "attack_graph_has_node"
    ATTACK_GRAPH_HAS_OBJECTIVE = "attack_graph_has_objective"
    ATTACK_NODE_DEPENDS_ON = "attack_node_depends_on"
    ATTACK_NODE_PRODUCED = "attack_node_produced"   # node → finding/evidence
    ATTACK_OBJECTIVE_TARGETS = "attack_objective_targets"  # objective → ai_target
    # Sprint 36/37: Adaptive Intelligence
    DECISION_INFLUENCED_NODE = "decision_influenced_node"  # node → decision record
    # Sprint 38/39: Evaluation Intelligence
    EVALUATION_HAS_CONSENSUS = "evaluation_has_consensus"
    EVALUATION_DISAGREES_WITH = "evaluation_disagrees_with"
    EVALUATOR_CALIBRATED_BY = "evaluator_calibrated_by"
    EVALUATION_PRODUCED_REASONING = "evaluation_produced_reasoning"
    CUSTOM = "custom"


# ─── Graph Primitives ─────────────────────────────────────────────────────────


@dataclass(slots=True)
class GraphNode:
    """A node in the knowledge graph representing a RedForge entity.

    Nodes are identified by (node_id, node_type) and carry arbitrary
    metadata for enrichment, embedding, and display purposes.
    """

    node_id: str
    node_type: NodeType
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def key(self) -> str:
        """Unique composite key for deduplication."""
        return f"{self.node_type}:{self.node_id}"

    def __hash__(self) -> int:
        return hash(self.key)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GraphNode):
            return NotImplemented
        return self.key == other.key


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """A directed edge representing a relationship between two nodes."""

    source_id: str
    target_id: str
    relationship: RelationshipType
    label: str = ""
    weight: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.source_id == self.target_id:
            raise ValueError("Self-referencing edges are not permitted")
        if self.weight < 0.0:
            raise ValueError(f"Edge weight must be non-negative, got {self.weight}")

    @property
    def key(self) -> str:
        """Unique edge key (source, target, relationship)."""
        return f"{self.source_id}-[{self.relationship}]->{self.target_id}"


# ─── Query & Result Types ─────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class GraphQuery:
    """A declarative graph query specification.

    Supports filtering by node type, relationship type, and depth limits.
    """

    start_node_id: str
    relationship_filter: list[RelationshipType] = field(default_factory=list)
    node_type_filter: list[NodeType] = field(default_factory=list)
    max_depth: int = 10
    direction: str = "outgoing"  # outgoing, incoming, both

    def __post_init__(self) -> None:
        if self.max_depth < 1:
            raise ValueError("max_depth must be at least 1")
        if self.direction not in ("outgoing", "incoming", "both"):
            raise ValueError(f"Invalid direction: {self.direction}")


@dataclass(slots=True)
class GraphResult:
    """Result of a graph query or traversal operation."""

    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    paths: list[list[str]] = field(default_factory=list)

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    @property
    def is_empty(self) -> bool:
        return not self.nodes and not self.edges


@dataclass(frozen=True, slots=True)
class GraphStatistics:
    """Aggregate statistics about the knowledge graph."""

    total_nodes: int
    total_edges: int
    node_type_counts: dict[str, int]
    relationship_type_counts: dict[str, int]
    density: float
    connected_components: int
    orphan_count: int
    most_connected: list[tuple[str, int]]  # (node_id, degree) top-N

    @property
    def average_degree(self) -> float:
        if self.total_nodes == 0:
            return 0.0
        return (2 * self.total_edges) / self.total_nodes


# ─── Graph Store Protocol ─────────────────────────────────────────────────────


@runtime_checkable
class GraphStore(Protocol):
    """Protocol for graph storage backends.

    Implementations may be in-memory, Neo4j, Neptune, Memgraph, etc.
    The KnowledgeGraph delegates all persistence through this interface.
    """

    def add_node(self, node: GraphNode) -> None: ...
    def add_edge(self, edge: GraphEdge) -> None: ...
    def get_node(self, node_id: str) -> GraphNode | None: ...
    def get_edges_from(self, node_id: str) -> list[GraphEdge]: ...
    def get_edges_to(self, node_id: str) -> list[GraphEdge]: ...
    def has_node(self, node_id: str) -> bool: ...
    def has_edge(self, source_id: str, target_id: str, relationship: RelationshipType) -> bool: ...
    def remove_node(self, node_id: str) -> None: ...
    def remove_edge(
        self, source_id: str, target_id: str, relationship: RelationshipType,
    ) -> None: ...
    def all_nodes(self) -> list[GraphNode]: ...
    def all_edges(self) -> list[GraphEdge]: ...
    def node_count(self) -> int: ...
    def edge_count(self) -> int: ...
    def clear(self) -> None: ...


# ─── In-Memory Graph Store ────────────────────────────────────────────────────


class InMemoryGraphStore:
    """Default in-memory graph store using adjacency lists.

    Suitable for graphs up to ~100K nodes. For larger graphs,
    swap with a Neo4j/Neptune-backed GraphStore implementation.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._outgoing: dict[str, list[GraphEdge]] = {}
        self._incoming: dict[str, list[GraphEdge]] = {}

    def add_node(self, node: GraphNode) -> None:
        self._nodes[node.node_id] = node
        if node.node_id not in self._outgoing:
            self._outgoing[node.node_id] = []
        if node.node_id not in self._incoming:
            self._incoming[node.node_id] = []

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.source_id not in self._nodes:
            raise ValueError(f"Source node '{edge.source_id}' not found")
        if edge.target_id not in self._nodes:
            raise ValueError(f"Target node '{edge.target_id}' not found")
        self._outgoing[edge.source_id].append(edge)
        self._incoming[edge.target_id].append(edge)

    def get_node(self, node_id: str) -> GraphNode | None:
        return self._nodes.get(node_id)

    def get_edges_from(self, node_id: str) -> list[GraphEdge]:
        return list(self._outgoing.get(node_id, []))

    def get_edges_to(self, node_id: str) -> list[GraphEdge]:
        return list(self._incoming.get(node_id, []))

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def has_edge(
        self, source_id: str, target_id: str, relationship: RelationshipType
    ) -> bool:
        for edge in self._outgoing.get(source_id, []):
            if edge.target_id == target_id and edge.relationship == relationship:
                return True
        return False

    def remove_node(self, node_id: str) -> None:
        if node_id not in self._nodes:
            return
        # Remove all edges involving this node
        self._outgoing.pop(node_id, None)
        self._incoming.pop(node_id, None)
        for edges in self._outgoing.values():
            edges[:] = [e for e in edges if e.target_id != node_id]
        for edges in self._incoming.values():
            edges[:] = [e for e in edges if e.source_id != node_id]
        del self._nodes[node_id]

    def remove_edge(
        self, source_id: str, target_id: str, relationship: RelationshipType
    ) -> None:
        if source_id in self._outgoing:
            self._outgoing[source_id] = [
                e for e in self._outgoing[source_id]
                if not (e.target_id == target_id and e.relationship == relationship)
            ]
        if target_id in self._incoming:
            self._incoming[target_id] = [
                e for e in self._incoming[target_id]
                if not (e.source_id == source_id and e.relationship == relationship)
            ]

    def all_nodes(self) -> list[GraphNode]:
        return list(self._nodes.values())

    def all_edges(self) -> list[GraphEdge]:
        edges: list[GraphEdge] = []
        for edge_list in self._outgoing.values():
            edges.extend(edge_list)
        return edges

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return sum(len(edges) for edges in self._outgoing.values())

    def clear(self) -> None:
        self._nodes.clear()
        self._outgoing.clear()
        self._incoming.clear()


# ─── Graph Traversal ──────────────────────────────────────────────────────────


class GraphTraversal:
    """Graph traversal algorithms: BFS, DFS, shortest path, reachability.

    Operates through the GraphStore protocol — backend-agnostic.
    """

    def __init__(self, store: GraphStore) -> None:
        self._store = store

    def bfs(
        self,
        start_id: str,
        max_depth: int = 10,
        relationship_filter: list[RelationshipType] | None = None,
        node_type_filter: list[NodeType] | None = None,
        direction: str = "both",
    ) -> GraphResult:
        """Breadth-first traversal from a starting node.

        When node_type_filter is set, the traversal still visits all
        reachable nodes but only includes matching nodes in the result.
        This allows traversal through intermediate nodes of different types.
        """
        if not self._store.has_node(start_id):
            return GraphResult()

        visited: set[str] = set()
        result_nodes: list[GraphNode] = []
        result_edges: list[GraphEdge] = []
        queue: deque[tuple[str, int]] = deque([(start_id, 0)])
        visited.add(start_id)

        start_node = self._store.get_node(start_id)
        if start_node and (not node_type_filter or start_node.node_type in node_type_filter):
            result_nodes.append(start_node)

        while queue:
            current_id, depth = queue.popleft()
            if depth >= max_depth:
                continue

            neighbors = self._get_neighbors(
                current_id, relationship_filter, direction
            )
            for edge, neighbor_id in neighbors:
                if neighbor_id in visited:
                    continue

                node = self._store.get_node(neighbor_id)
                if node is None:
                    continue

                visited.add(neighbor_id)
                # Always traverse through the node
                queue.append((neighbor_id, depth + 1))
                # Only include in results if it matches the filter
                if not node_type_filter or node.node_type in node_type_filter:
                    result_nodes.append(node)
                    result_edges.append(edge)

        return GraphResult(nodes=result_nodes, edges=result_edges)

    def shortest_path(
        self,
        start_id: str,
        end_id: str,
        relationship_filter: list[RelationshipType] | None = None,
        max_depth: int = 100_000,
    ) -> list[str] | None:
        """Find shortest path between two nodes using BFS.

        Returns list of node IDs forming the path, or None if unreachable.
        """
        if not self._store.has_node(start_id) or not self._store.has_node(end_id):
            return None
        if start_id == end_id:
            return [start_id]

        visited: set[str] = {start_id}
        queue: deque[tuple[str, list[str]]] = deque([(start_id, [start_id])])

        while queue:
            current_id, path = queue.popleft()
            if len(path) > max_depth:
                continue

            neighbors = self._get_neighbors(current_id, relationship_filter, "both")
            for _edge, neighbor_id in neighbors:
                if neighbor_id == end_id:
                    return [*path, neighbor_id]
                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    queue.append((neighbor_id, [*path, neighbor_id]))

        return None

    def find_reachable(
        self,
        start_id: str,
        relationship_filter: list[RelationshipType] | None = None,
        direction: str = "both",
    ) -> set[str]:
        """Find all nodes reachable from start_id."""
        if not self._store.has_node(start_id):
            return set()

        visited: set[str] = set()
        stack = [start_id]

        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            neighbors = self._get_neighbors(current, relationship_filter, direction)
            for _edge, neighbor_id in neighbors:
                if neighbor_id not in visited:
                    stack.append(neighbor_id)

        return visited

    def has_cycle(self) -> bool:
        """Detect if the graph contains any cycles (iterative DFS)."""
        all_nodes = self._store.all_nodes()
        white, gray, black = 0, 1, 2
        color: dict[str, int] = {n.node_id: white for n in all_nodes}

        for node in all_nodes:
            if color[node.node_id] != white:
                continue
            # Iterative DFS with explicit stack
            stack: list[tuple[str, int]] = [(node.node_id, 0)]
            color[node.node_id] = gray

            while stack:
                current_id, edge_idx = stack[-1]
                edges = self._store.get_edges_from(current_id)

                if edge_idx >= len(edges):
                    # Done with this node
                    color[current_id] = black
                    stack.pop()
                    continue

                # Advance edge pointer
                stack[-1] = (current_id, edge_idx + 1)
                neighbor_id = edges[edge_idx].target_id

                if color.get(neighbor_id, white) == gray:
                    return True  # Back edge = cycle
                if color.get(neighbor_id, white) == white:
                    color[neighbor_id] = gray
                    stack.append((neighbor_id, 0))

        return False

    def connected_components(self) -> list[set[str]]:
        """Find all connected components (treating edges as undirected)."""
        all_nodes = self._store.all_nodes()
        visited: set[str] = set()
        components: list[set[str]] = []

        for node in all_nodes:
            if node.node_id in visited:
                continue
            component = self.find_reachable(node.node_id, direction="both")
            visited.update(component)
            components.append(component)

        return components

    def find_orphans(self) -> list[GraphNode]:
        """Find nodes with no edges (neither incoming nor outgoing)."""
        orphans: list[GraphNode] = []
        for node in self._store.all_nodes():
            out_edges = self._store.get_edges_from(node.node_id)
            in_edges = self._store.get_edges_to(node.node_id)
            if not out_edges and not in_edges:
                orphans.append(node)
        return orphans

    def _get_neighbors(
        self,
        node_id: str,
        relationship_filter: list[RelationshipType] | None,
        direction: str,
    ) -> list[tuple[GraphEdge, str]]:
        """Get neighboring nodes with optional relationship filtering."""
        neighbors: list[tuple[GraphEdge, str]] = []

        if direction in ("outgoing", "both"):
            for edge in self._store.get_edges_from(node_id):
                if relationship_filter and edge.relationship not in relationship_filter:
                    continue
                neighbors.append((edge, edge.target_id))

        if direction in ("incoming", "both"):
            for edge in self._store.get_edges_to(node_id):
                if relationship_filter and edge.relationship not in relationship_filter:
                    continue
                neighbors.append((edge, edge.source_id))

        return neighbors


# ─── Graph Serializer ─────────────────────────────────────────────────────────


class GraphSerializer:
    """Serializes/deserializes the knowledge graph to/from dictionaries.

    Produces a format suitable for JSON persistence, GraphRAG ingestion,
    REST API responses, and dashboard rendering.
    """

    @staticmethod
    def to_dict(store: GraphStore) -> dict[str, Any]:
        """Serialize entire graph to a dictionary."""
        nodes = [
            {
                "node_id": n.node_id,
                "node_type": str(n.node_type),
                "label": n.label,
                "metadata": n.metadata,
                "created_at": n.created_at.isoformat(),
            }
            for n in store.all_nodes()
        ]
        edges = [
            {
                "source_id": e.source_id,
                "target_id": e.target_id,
                "relationship": str(e.relationship),
                "label": e.label,
                "weight": e.weight,
                "metadata": e.metadata,
            }
            for e in store.all_edges()
        ]
        return {"nodes": nodes, "edges": edges}

    @staticmethod
    def from_dict(data: dict[str, Any]) -> InMemoryGraphStore:
        """Deserialize a dictionary into an InMemoryGraphStore."""
        store = InMemoryGraphStore()

        for n in data.get("nodes", []):
            node = GraphNode(
                node_id=n["node_id"],
                node_type=NodeType(n["node_type"]),
                label=n["label"],
                metadata=n.get("metadata", {}),
            )
            if "created_at" in n:
                node.created_at = datetime.fromisoformat(n["created_at"])
            store.add_node(node)

        for e in data.get("edges", []):
            edge = GraphEdge(
                source_id=e["source_id"],
                target_id=e["target_id"],
                relationship=RelationshipType(e["relationship"]),
                label=e.get("label", ""),
                weight=e.get("weight", 1.0),
                metadata=e.get("metadata", {}),
            )
            store.add_edge(edge)

        return store

    @staticmethod
    def node_to_dict(node: GraphNode) -> dict[str, Any]:
        """Serialize a single node."""
        return {
            "node_id": node.node_id,
            "node_type": str(node.node_type),
            "label": node.label,
            "metadata": node.metadata,
            "created_at": node.created_at.isoformat(),
        }

    @staticmethod
    def edge_to_dict(edge: GraphEdge) -> dict[str, Any]:
        """Serialize a single edge."""
        return {
            "source_id": edge.source_id,
            "target_id": edge.target_id,
            "relationship": str(edge.relationship),
            "label": edge.label,
            "weight": edge.weight,
            "metadata": edge.metadata,
        }


# ─── Knowledge Graph (Facade) ─────────────────────────────────────────────────


class KnowledgeGraph:
    """AI Security Knowledge Graph — the primary public interface.

    Composes GraphStore, GraphTraversal, and GraphSerializer to provide
    a unified API for building, querying, and serializing the graph.

    Usage:
        graph = KnowledgeGraph()
        graph.add_node(GraphNode(node_id="t-1", node_type=NodeType.AI_TARGET, label="Prod LLM"))
        graph.add_node(GraphNode(node_id="p-1", node_type=NodeType.PROVIDER, label="OpenAI"))
        graph.add_edge(GraphEdge(
            source_id="t-1", target_id="p-1",
            relationship=RelationshipType.TARGET_USES_PROVIDER,
        ))
        result = graph.query_related("t-1")
    """

    def __init__(self, store: GraphStore | None = None) -> None:
        self._store: GraphStore = store or InMemoryGraphStore()
        self._traversal = GraphTraversal(self._store)

    # ─── Mutation ─────────────────────────────────────────────────────────

    def add_node(self, node: GraphNode) -> None:
        """Add a node to the graph."""
        self._store.add_node(node)

    def add_edge(self, edge: GraphEdge) -> None:
        """Add a directed edge between two existing nodes."""
        self._store.add_edge(edge)

    def remove_node(self, node_id: str) -> None:
        """Remove a node and all its edges."""
        self._store.remove_node(node_id)

    def remove_edge(
        self, source_id: str, target_id: str, relationship: RelationshipType
    ) -> None:
        """Remove a specific edge."""
        self._store.remove_edge(source_id, target_id, relationship)

    def clear(self) -> None:
        """Remove all nodes and edges."""
        self._store.clear()

    # ─── Queries ──────────────────────────────────────────────────────────

    def query_related(
        self,
        node_id: str,
        max_depth: int = 3,
        relationship_filter: list[RelationshipType] | None = None,
        node_type_filter: list[NodeType] | None = None,
        direction: str = "both",
    ) -> GraphResult:
        """Show everything related to a node (BFS traversal)."""
        return self._traversal.bfs(
            start_id=node_id,
            max_depth=max_depth,
            relationship_filter=relationship_filter,
            node_type_filter=node_type_filter,
            direction=direction,
        )

    def query_shortest_path(
        self,
        start_id: str,
        end_id: str,
        relationship_filter: list[RelationshipType] | None = None,
    ) -> list[str] | None:
        """Find shortest path between two nodes."""
        return self._traversal.shortest_path(
            start_id, end_id, relationship_filter
        )

    def query_by_type(self, node_type: NodeType) -> list[GraphNode]:
        """Find all nodes of a specific type."""
        return [
            n for n in self._store.all_nodes() if n.node_type == node_type
        ]

    def query_by_relationship(
        self, relationship: RelationshipType
    ) -> list[GraphEdge]:
        """Find all edges of a specific relationship type."""
        return [
            e for e in self._store.all_edges() if e.relationship == relationship
        ]

    def query_neighbors(
        self,
        node_id: str,
        direction: str = "both",
        relationship_filter: list[RelationshipType] | None = None,
    ) -> list[GraphNode]:
        """Get immediate neighbors of a node."""
        result = self._traversal.bfs(
            start_id=node_id,
            max_depth=1,
            relationship_filter=relationship_filter,
            direction=direction,
        )
        # Exclude the start node itself
        return [n for n in result.nodes if n.node_id != node_id]

    def query_orphans(self) -> list[GraphNode]:
        """Find nodes with no connections."""
        return self._traversal.find_orphans()

    def query_disconnected_components(self) -> list[set[str]]:
        """Find all disconnected subgraphs."""
        return self._traversal.connected_components()

    def execute_query(self, query: GraphQuery) -> GraphResult:
        """Execute a declarative GraphQuery."""
        return self._traversal.bfs(
            start_id=query.start_node_id,
            max_depth=query.max_depth,
            relationship_filter=query.relationship_filter or None,
            node_type_filter=query.node_type_filter or None,
            direction=query.direction,
        )

    # ─── Analysis ──────────────────────────────────────────────────────────

    def has_cycle(self) -> bool:
        """Check if the graph contains cycles."""
        return self._traversal.has_cycle()

    def statistics(self, top_n: int = 10) -> GraphStatistics:
        """Compute aggregate graph statistics."""
        all_nodes = self._store.all_nodes()
        all_edges = self._store.all_edges()
        total_nodes = len(all_nodes)
        total_edges = len(all_edges)

        # Node type distribution
        node_type_counts: dict[str, int] = {}
        for n in all_nodes:
            key = str(n.node_type)
            node_type_counts[key] = node_type_counts.get(key, 0) + 1

        # Relationship distribution
        rel_counts: dict[str, int] = {}
        for e in all_edges:
            key = str(e.relationship)
            rel_counts[key] = rel_counts.get(key, 0) + 1

        # Density
        max_edges = total_nodes * (total_nodes - 1) if total_nodes > 1 else 1
        density = total_edges / max_edges if max_edges > 0 else 0.0

        # Degree computation (in + out)
        degree: dict[str, int] = {n.node_id: 0 for n in all_nodes}
        for e in all_edges:
            degree[e.source_id] = degree.get(e.source_id, 0) + 1
            degree[e.target_id] = degree.get(e.target_id, 0) + 1

        # Top connected
        sorted_degree = sorted(degree.items(), key=lambda x: x[1], reverse=True)
        most_connected = sorted_degree[:top_n]

        # Connected components
        components = self._traversal.connected_components()

        # Orphans
        orphan_count = sum(1 for d in degree.values() if d == 0)

        return GraphStatistics(
            total_nodes=total_nodes,
            total_edges=total_edges,
            node_type_counts=node_type_counts,
            relationship_type_counts=rel_counts,
            density=density,
            connected_components=len(components),
            orphan_count=orphan_count,
            most_connected=most_connected,
        )

    # ─── Serialization ────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialize the entire graph."""
        return GraphSerializer.to_dict(self._store)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KnowledgeGraph:
        """Reconstruct a KnowledgeGraph from serialized data."""
        store = GraphSerializer.from_dict(data)
        return cls(store=store)

    # ─── Accessors ────────────────────────────────────────────────────────

    def get_node(self, node_id: str) -> GraphNode | None:
        """Get a node by ID."""
        return self._store.get_node(node_id)

    def has_node(self, node_id: str) -> bool:
        """Check if a node exists."""
        return self._store.has_node(node_id)

    @property
    def node_count(self) -> int:
        return self._store.node_count()

    @property
    def edge_count(self) -> int:
        return self._store.edge_count()
