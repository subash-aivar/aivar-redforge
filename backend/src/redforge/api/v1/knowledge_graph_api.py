"""Knowledge Graph REST API endpoints.

DISPOSITION (M4, Capability 12): the Knowledge Graph is a single
process-wide in-memory store (application/knowledge_graph.py) that
predates the M3/M4 tenant-scoped persistence architecture. It is kept
as a reusable graph-primitive/legacy internal path (disposition D:
"reusable graph primitive with incorrect tenancy assumptions") rather
than deprecated outright, since ValidationService still populates it —
but the previously-open P0 (any authenticated user of any organization
could read/mutate any other organization's nodes/edges by ID, since the
in-memory keyspace was global) is fixed here at the API boundary:
every node/edge identifier this router accepts or returns is
tenant-scoped by prefixing the caller's verified `organization_id`
(never client-supplied) onto the underlying graph key before touching
the shared store, and stripped back off before the ID is returned to
the caller. Tenant A's "t-1" and tenant B's "t-1" are therefore
distinct underlying nodes that cannot collide, be overwritten, or be
read cross-tenant — a guessed foreign node_id 404s identically to a
nonexistent one, matching the M3 asset/connector isolation contract.

Remaining, explicitly accepted limitation: `/stats` and `/orphans`
report GLOBAL aggregate counts (total_nodes, total_edges, density,
etc.) across all tenants' scoped nodes — this discloses only numeric
totals, never node identity or content, and is judged acceptable at M4
scope (documented, not silently left as the prior full-content P0).
Full per-tenant aggregate stats would require KnowledgeGraph itself to
support a scoped iteration API, a larger change than an API-boundary
fix — the tenant-scoped Security Graph (M4's new bounded context,
api/v1/security_graph.py) is the durable replacement path for any
caller that needs a real per-tenant graph; this legacy KG surface
should not be extended further.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_knowledge_graph
from redforge.api.security import TenantContext, require_permission
from redforge.application.knowledge_graph import (
    GraphEdge,
    GraphNode,
    KnowledgeGraph,
    NodeType,
    RelationshipType,
)
from redforge.domain.identity.value_objects import Permission

router = APIRouter(prefix="/knowledge-graph", tags=["knowledge-graph"])


def _scope(organization_id: str, raw_id: str) -> str:
    """Namespaces a caller-supplied node/edge endpoint ID under the
    verified tenant so the shared in-memory keyspace can never collide
    or be read across organizations."""
    return f"{organization_id}:{raw_id}"


def _unscope(organization_id: str, scoped_id: str) -> str:
    prefix = f"{organization_id}:"
    return scoped_id[len(prefix) :] if scoped_id.startswith(prefix) else scoped_id


# ─── Request/Response Models ──────────────────────────────────────────────────


class AddNodeRequest(BaseModel):
    node_id: str = Field(..., min_length=1)
    node_type: str = Field(..., min_length=1)
    label: str = Field(..., min_length=1)
    metadata: dict[str, object] = Field(default_factory=dict)


class AddEdgeRequest(BaseModel):
    source_id: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)
    relationship: str = Field(..., min_length=1)
    label: str = ""
    weight: float = Field(default=1.0, ge=0.0)


class GraphNodeResponse(BaseModel):
    node_id: str
    node_type: str
    label: str
    metadata: dict[str, object]


class GraphEdgeResponse(BaseModel):
    source_id: str
    target_id: str
    relationship: str
    label: str
    weight: float


class GraphQueryRequest(BaseModel):
    start_node_id: str
    max_depth: int = Field(default=3, ge=1, le=50)
    relationship_filter: list[str] = Field(default_factory=list)
    node_type_filter: list[str] = Field(default_factory=list)
    direction: str = Field(default="both", pattern=r"^(outgoing|incoming|both)$")


class GraphQueryResponse(BaseModel):
    nodes: list[GraphNodeResponse]
    edges: list[GraphEdgeResponse]


class GraphStatsResponse(BaseModel):
    total_nodes: int
    total_edges: int
    node_type_counts: dict[str, int]
    relationship_type_counts: dict[str, int]
    density: float
    connected_components: int
    orphan_count: int
    average_degree: float


class ShortestPathRequest(BaseModel):
    start_id: str
    end_id: str
    relationship_filter: list[str] = Field(default_factory=list)


class ShortestPathResponse(BaseModel):
    path: list[str] | None
    length: int


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post("/nodes", response_model=GraphNodeResponse, status_code=201)
async def add_node(
    body: AddNodeRequest,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_MANAGE)),
    graph: KnowledgeGraph = Depends(get_knowledge_graph),
) -> GraphNodeResponse:
    """Add a node to the knowledge graph, scoped to the caller's org."""
    node_type = NodeType(body.node_type) if body.node_type in NodeType else NodeType.CUSTOM
    node = GraphNode(
        node_id=_scope(tenant.organization_id, body.node_id), node_type=node_type,
        label=body.label, metadata=body.metadata,
    )
    graph.add_node(node)
    return GraphNodeResponse(
        node_id=body.node_id, node_type=str(node.node_type),
        label=node.label, metadata=node.metadata,
    )


@router.post("/edges", response_model=GraphEdgeResponse, status_code=201)
async def add_edge(
    body: AddEdgeRequest,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_MANAGE)),
    graph: KnowledgeGraph = Depends(get_knowledge_graph),
) -> GraphEdgeResponse:
    """Add an edge to the knowledge graph, scoped to the caller's org."""
    rel = (
        RelationshipType(body.relationship)
        if body.relationship in RelationshipType
        else RelationshipType.CUSTOM
    )
    edge = GraphEdge(
        source_id=_scope(tenant.organization_id, body.source_id),
        target_id=_scope(tenant.organization_id, body.target_id),
        relationship=rel, label=body.label, weight=body.weight,
    )
    graph.add_edge(edge)
    return GraphEdgeResponse(
        source_id=body.source_id, target_id=body.target_id,
        relationship=str(edge.relationship), label=edge.label,
        weight=edge.weight,
    )


@router.post("/query", response_model=GraphQueryResponse)
async def query_graph(
    body: GraphQueryRequest,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    graph: KnowledgeGraph = Depends(get_knowledge_graph),
) -> GraphQueryResponse:
    """Query the knowledge graph with BFS traversal, scoped to the
    caller's org — traversal can never leave the tenant's namespace
    since every node/edge key it was ever seeded with is prefixed."""
    rel_filter = (
        [RelationshipType(r) for r in body.relationship_filter if r in RelationshipType]
        or None
    )
    type_filter = (
        [NodeType(t) for t in body.node_type_filter if t in NodeType]
        or None
    )
    result = graph.query_related(
        _scope(tenant.organization_id, body.start_node_id), max_depth=body.max_depth,
        relationship_filter=rel_filter, node_type_filter=type_filter,
        direction=body.direction,
    )
    return GraphQueryResponse(
        nodes=[
            GraphNodeResponse(
                node_id=_unscope(tenant.organization_id, n.node_id), node_type=str(n.node_type),
                label=n.label, metadata=n.metadata,
            )
            for n in result.nodes
        ],
        edges=[
            GraphEdgeResponse(
                source_id=_unscope(tenant.organization_id, e.source_id),
                target_id=_unscope(tenant.organization_id, e.target_id),
                relationship=str(e.relationship), label=e.label,
                weight=e.weight,
            )
            for e in result.edges
        ],
    )


@router.post("/shortest-path", response_model=ShortestPathResponse)
async def shortest_path(
    body: ShortestPathRequest,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    graph: KnowledgeGraph = Depends(get_knowledge_graph),
) -> ShortestPathResponse:
    """Find the shortest path between two nodes, scoped to the caller's org."""
    path = graph.query_shortest_path(
        _scope(tenant.organization_id, body.start_id), _scope(tenant.organization_id, body.end_id),
    )
    unscoped_path = [_unscope(tenant.organization_id, p) for p in path] if path else path
    return ShortestPathResponse(
        path=unscoped_path, length=len(unscoped_path) if unscoped_path else 0,
    )


@router.get("/stats", response_model=GraphStatsResponse)
async def graph_statistics(
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    graph: KnowledgeGraph = Depends(get_knowledge_graph),
) -> GraphStatsResponse:
    """Global aggregate counts across all tenants' scoped nodes — see
    module docstring's documented limitation. Discloses only numeric
    totals, never node identity or content."""
    stats = graph.statistics()
    return GraphStatsResponse(
        total_nodes=stats.total_nodes, total_edges=stats.total_edges,
        node_type_counts=stats.node_type_counts,
        relationship_type_counts=stats.relationship_type_counts,
        density=stats.density, connected_components=stats.connected_components,
        orphan_count=stats.orphan_count, average_degree=stats.average_degree,
    )


@router.get("/orphans", response_model=list[GraphNodeResponse])
async def find_orphans(
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    graph: KnowledgeGraph = Depends(get_knowledge_graph),
) -> list[GraphNodeResponse]:
    """Find nodes with no connections, scoped to the caller's org."""
    orphans = graph.query_orphans()
    prefix = f"{tenant.organization_id}:"
    return [
        GraphNodeResponse(
            node_id=_unscope(tenant.organization_id, n.node_id), node_type=str(n.node_type),
            label=n.label, metadata=n.metadata,
        )
        for n in orphans
        if n.node_id.startswith(prefix)
    ]


@router.get("/nodes/{node_id}", response_model=GraphNodeResponse)
async def get_node(
    node_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    graph: KnowledgeGraph = Depends(get_knowledge_graph),
) -> GraphNodeResponse:
    """Get a specific node by ID, scoped to the caller's org. A guessed
    foreign-tenant node_id 404s identically to a nonexistent one."""
    from redforge.core.exceptions import NotFoundError

    node = graph.get_node(_scope(tenant.organization_id, node_id))
    if node is None:
        raise NotFoundError("GraphNode", node_id)
    return GraphNodeResponse(
        node_id=node_id, node_type=str(node.node_type),
        label=node.label, metadata=node.metadata,
    )


@router.delete("/nodes/{node_id}", status_code=204)
async def remove_node(
    node_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_MANAGE)),
    graph: KnowledgeGraph = Depends(get_knowledge_graph),
) -> None:
    """Remove a node from the knowledge graph, scoped to the caller's org."""
    graph.remove_node(_scope(tenant.organization_id, node_id))
