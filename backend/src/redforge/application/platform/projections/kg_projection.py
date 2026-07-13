"""KGProjection — Knowledge Graph as a projection consumer.

The KG is NOT replaced. It becomes one projection consumer of the Platform
event stream. This projection listens to relevant event types and updates
the existing KnowledgeGraph accordingly.

This is the anti-corruption layer between the Platform event backbone and
the existing Sprint 13+ KnowledgeGraph implementation.
"""

from __future__ import annotations

from datetime import UTC, datetime

from redforge.application.knowledge_graph import (
    GraphEdge,
    GraphNode,
    KnowledgeGraph,
    NodeType,
    RelationshipType,
)
from redforge.application.platform.projection_engine import (
    InMemoryReadModelRepository,
    ProjectionEngine,
)
from redforge.application.platform.projections.base import ProjectionBase
from redforge.domain.platform.events import EventEnvelope
from redforge.domain.platform.read_models import KnowledgeGraphReadModel


def _utc_now() -> datetime:
    return datetime.now(UTC)


class KGProjection(ProjectionBase):
    """Feeds relevant platform events into the existing KnowledgeGraph."""

    projection_name = "knowledge_graph"

    def __init__(
        self,
        graph: KnowledgeGraph,
        repo: InMemoryReadModelRepository,
    ) -> None:
        self._graph = graph
        self._repo = repo
        self._last_positions: dict[str, int] = {}

    def register_with(self, engine: ProjectionEngine) -> None:
        pn = self.projection_name
        engine.register(pn, "inventory.AIAssetCreated", self._handle_asset_created)
        engine.register(pn, "asset.AssetRegistered", self._handle_asset_created)
        engine.register(pn, "connector.ConnectorRegistered", self._handle_connector)
        engine.register(pn, "connector.ConnectorEnabled", self._handle_connector)
        engine.register(pn, "findings.FindingCreated", self._handle_finding)
        engine.register(pn, "campaign.CampaignCreated", self._handle_campaign)

    async def _handle_asset_created(self, envelope: EventEnvelope) -> None:
        node_id = f"asset:{envelope.aggregate_id}"
        self._graph.add_node(GraphNode(
            node_id=node_id,
            node_type=NodeType.AI_TARGET,
            label=envelope.metadata.get_custom("name") or envelope.aggregate_id,
            metadata={
                "aggregate_id": envelope.aggregate_id,
                "organization_id": envelope.organization_id,
                "event_type": envelope.event_type,
            },
        ))
        org_node = f"org:{envelope.organization_id}"
        if self._graph.has_node(org_node):
            self._graph.add_edge(GraphEdge(
                source_id=node_id,
                target_id=org_node,
                relationship=RelationshipType.CONNECTOR_BELONGS_TO_ORG,
                label="asset belongs to org",
            ))
        self._last_positions[envelope.organization_id] = envelope.global_position
        await self._persist(envelope.organization_id)

    async def _handle_connector(self, envelope: EventEnvelope) -> None:
        node_id = f"connector:{envelope.aggregate_id}"
        self._graph.add_node(GraphNode(
            node_id=node_id,
            node_type=NodeType.CONNECTOR,
            label=envelope.metadata.get_custom("name") or envelope.aggregate_id,
            metadata={
                "aggregate_id": envelope.aggregate_id,
                "organization_id": envelope.organization_id,
                "event_type": envelope.event_type,
            },
        ))
        self._last_positions[envelope.organization_id] = envelope.global_position
        await self._persist(envelope.organization_id)

    async def _handle_finding(self, envelope: EventEnvelope) -> None:
        node_id = f"finding:{envelope.aggregate_id}"
        self._graph.add_node(GraphNode(
            node_id=node_id,
            node_type=NodeType.FINDING,
            label=f"Finding {envelope.aggregate_id[:8]}",
            metadata={
                "aggregate_id": envelope.aggregate_id,
                "organization_id": envelope.organization_id,
                "severity": envelope.metadata.get_custom("severity") or "unknown",
            },
        ))
        self._last_positions[envelope.organization_id] = envelope.global_position
        await self._persist(envelope.organization_id)

    async def _handle_campaign(self, envelope: EventEnvelope) -> None:
        node_id = f"campaign:{envelope.aggregate_id}"
        self._graph.add_node(GraphNode(
            node_id=node_id,
            node_type=NodeType.CAMPAIGN,
            label=envelope.metadata.get_custom("name") or f"Campaign {envelope.aggregate_id[:8]}",
            metadata={
                "aggregate_id": envelope.aggregate_id,
                "organization_id": envelope.organization_id,
            },
        ))
        self._last_positions[envelope.organization_id] = envelope.global_position
        await self._persist(envelope.organization_id)

    async def _persist(self, org: str) -> None:
        model = KnowledgeGraphReadModel(
            organization_id=org,
            total_nodes=self._graph.node_count,
            total_edges=self._graph.edge_count,
            nodes_by_type={},
            last_updated_at=_utc_now(),
            last_event_position=self._last_positions.get(org, 0),
        )
        await self._repo.save(model)

    async def get(self, organization_id: str) -> KnowledgeGraphReadModel | None:
        return await self._repo.load("knowledge_graph", organization_id)
