"""TenantSecurityGraphService — M4.

Every method requires organization_id and enforces it at the repository
query level (never fetch-then-filter). No method returns unbounded
graph data — overview/traversal are always limit/depth bounded.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from redforge.core.exceptions import NotFoundError, ValidationError
from redforge.infrastructure.database.repositories.security_graph_repository import (
    SecurityGraphRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.infrastructure.database.models.security_graph import (
        SecurityGraphEdgeModel,
        SecurityGraphNodeModel,
    )

MAX_TRAVERSAL_DEPTH = 6
MAX_PATH_RESULTS = 20
MAX_OVERVIEW_LIMIT = 500


class Direction(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BOTH = "both"


@dataclass(frozen=True, slots=True)
class NodeDTO:
    id: str
    node_kind: str
    label: str
    source_domain: str
    source_entity_id: str
    attributes: dict[str, str]
    ontology_version: int

    @classmethod
    def from_model(cls, m: SecurityGraphNodeModel) -> NodeDTO:
        return cls(
            id=m.id,
            node_kind=m.node_kind,
            label=m.label,
            source_domain=m.source_domain,
            source_entity_id=m.source_entity_id,
            attributes=dict(m.attributes),
            ontology_version=m.ontology_version,
        )


@dataclass(frozen=True, slots=True)
class EdgeDTO:
    id: str
    source_node_id: str
    target_node_id: str
    relationship_kind: str
    provenance: str

    @classmethod
    def from_model(cls, m: SecurityGraphEdgeModel) -> EdgeDTO:
        return cls(
            id=m.id,
            source_node_id=m.source_node_id,
            target_node_id=m.target_node_id,
            relationship_kind=m.relationship_kind,
            provenance=m.provenance,
        )


@dataclass(frozen=True, slots=True)
class GraphOverviewDTO:
    nodes: list[NodeDTO]
    edges: list[EdgeDTO]
    node_count: int
    truncated: bool


@dataclass(frozen=True, slots=True)
class NodeDetailDTO:
    node: NodeDTO
    inbound_count: int
    outbound_count: int


@dataclass(frozen=True, slots=True)
class NeighborDTO:
    node: NodeDTO
    via_edge: EdgeDTO


@dataclass(frozen=True, slots=True)
class SecurityRelationshipPathDTO:
    """A bounded, cycle-safe chain of nodes/edges. Deliberately NOT
    called an "attack path" — no exploitability/probability is
    computed; it is a proven graph-relationship chain only."""

    node_ids: list[str]
    edge_ids: list[str]


class TenantSecurityGraphService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def overview(
        self, organization_id: str, node_kind: str | None = None, limit: int = 100
    ) -> GraphOverviewDTO:
        bounded_limit = min(limit, MAX_OVERVIEW_LIMIT)
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SecurityGraphRepository(uow.session)
            nodes = await repo.list_nodes_for_org(organization_id, limit=bounded_limit + 1)
            edges = await repo.list_edges_for_org(organization_id, limit=MAX_OVERVIEW_LIMIT * 4)

        truncated = len(nodes) > bounded_limit
        nodes = nodes[:bounded_limit]
        if node_kind is not None:
            nodes = [n for n in nodes if n.node_kind == node_kind]
        node_ids = {n.id for n in nodes}
        edges = [e for e in edges if e.source_node_id in node_ids and e.target_node_id in node_ids]
        return GraphOverviewDTO(
            nodes=[NodeDTO.from_model(n) for n in nodes],
            edges=[EdgeDTO.from_model(e) for e in edges],
            node_count=len(nodes),
            truncated=truncated,
        )

    async def get_node(self, organization_id: str, node_id: str) -> NodeDetailDTO:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SecurityGraphRepository(uow.session)
            node = await repo.get_node_by_id_for_org(node_id, organization_id)
            if node is None:
                raise NotFoundError("SecurityGraphNode", node_id)
            inbound = await repo.list_inbound_edges(organization_id, node_id)
            outbound = await repo.list_outbound_edges(organization_id, node_id)
        return NodeDetailDTO(
            node=NodeDTO.from_model(node),
            inbound_count=len(inbound),
            outbound_count=len(outbound),
        )

    async def get_neighbors(
        self, organization_id: str, node_id: str, direction: Direction = Direction.BOTH
    ) -> list[NeighborDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SecurityGraphRepository(uow.session)
            node = await repo.get_node_by_id_for_org(node_id, organization_id)
            if node is None:
                raise NotFoundError("SecurityGraphNode", node_id)

            results: list[NeighborDTO] = []
            if direction in (Direction.OUTBOUND, Direction.BOTH):
                for edge in await repo.list_outbound_edges(organization_id, node_id):
                    target = await repo.get_node_by_id_for_org(
                        edge.target_node_id, organization_id
                    )
                    if target is not None:
                        via = EdgeDTO.from_model(edge)
                        results.append(NeighborDTO(node=NodeDTO.from_model(target), via_edge=via))
            if direction in (Direction.INBOUND, Direction.BOTH):
                for edge in await repo.list_inbound_edges(organization_id, node_id):
                    source = await repo.get_node_by_id_for_org(
                        edge.source_node_id, organization_id
                    )
                    if source is not None:
                        via = EdgeDTO.from_model(edge)
                        results.append(NeighborDTO(node=NodeDTO.from_model(source), via_edge=via))
        return results

    async def find_paths(
        self,
        organization_id: str,
        start_node_id: str,
        end_node_id: str,
        max_depth: int = 4,
        relationship_kinds: list[str] | None = None,
    ) -> list[SecurityRelationshipPathDTO]:
        """Bounded, cycle-safe BFS over tenant-scoped edges only.
        max_depth is server-clamped to MAX_TRAVERSAL_DEPTH regardless of
        caller input; result count is clamped to MAX_PATH_RESULTS."""
        depth = min(max(max_depth, 1), MAX_TRAVERSAL_DEPTH)

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SecurityGraphRepository(uow.session)
            start = await repo.get_node_by_id_for_org(start_node_id, organization_id)
            end = await repo.get_node_by_id_for_org(end_node_id, organization_id)
            if start is None:
                raise NotFoundError("SecurityGraphNode", start_node_id)
            if end is None:
                raise NotFoundError("SecurityGraphNode", end_node_id)

            all_edges = await repo.list_edges_for_org(organization_id, limit=MAX_OVERVIEW_LIMIT * 4)

        if relationship_kinds:
            unknown = set(relationship_kinds) - _known_kinds()
            if unknown:
                raise ValidationError(f"Unknown relationship kind filter: {sorted(unknown)}")
            all_edges = [e for e in all_edges if e.relationship_kind in relationship_kinds]

        adjacency: dict[str, list[SecurityGraphEdgeModel]] = {}
        for e in all_edges:
            adjacency.setdefault(e.source_node_id, []).append(e)

        paths: list[SecurityRelationshipPathDTO] = []
        # (current_node_id, node_path, edge_path, visited_set)
        queue: list[tuple[str, list[str], list[str], frozenset[str]]] = [
            (start_node_id, [start_node_id], [], frozenset({start_node_id}))
        ]
        while queue and len(paths) < MAX_PATH_RESULTS:
            current, node_path, edge_path, visited = queue.pop(0)
            if current == end_node_id and len(node_path) > 1:
                paths.append(SecurityRelationshipPathDTO(node_ids=node_path, edge_ids=edge_path))
                continue
            if len(node_path) - 1 >= depth:
                continue
            for edge in adjacency.get(current, []):
                if edge.target_node_id in visited:
                    continue  # cycle-safe: never revisit a node in this path
                queue.append(
                    (
                        edge.target_node_id,
                        [*node_path, edge.target_node_id],
                        [*edge_path, edge.id],
                        visited | {edge.target_node_id},
                    )
                )
        return paths


def _known_kinds() -> set[str]:
    from redforge.domain.security_graph.ontology import EdgeKind

    return {k.value for k in EdgeKind}
