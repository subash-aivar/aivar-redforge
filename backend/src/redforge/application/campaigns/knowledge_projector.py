"""Campaign Knowledge Graph projector.

Projects a completed (or failed) Campaign aggregate into the shared
KnowledgeGraph. Implements CampaignKnowledgeProjectorPort.

Nodes added:
  - NodeType.CAMPAIGN — one node per campaign
Edges added:
  - CAMPAIGN_COVERS_TARGET  → one per target in campaign.target_ids
  - CAMPAIGN_REGRESSED_FROM → only when drift_summary.regression_detected

KnowledgeGraph API:
  - GraphNode uses `metadata: dict` (not `properties`)
  - GraphEdge uses `relationship: RelationshipType` (not `relationship_type`)
"""

from __future__ import annotations

from redforge.application.knowledge_graph import (
    GraphEdge,
    GraphNode,
    KnowledgeGraph,
    NodeType,
    RelationshipType,
)
from redforge.domain.campaigns.entity import Campaign


class CampaignKnowledgeGraphProjector:
    """Projects Campaign nodes and relationships into the KnowledgeGraph."""

    def __init__(self, graph: KnowledgeGraph) -> None:
        self._graph = graph

    def project_campaign(self, campaign: Campaign) -> int:
        """Add Campaign node + CAMPAIGN_COVERS_TARGET edges. Returns nodes added."""
        added = 0

        label = (
            f"Campaign:{campaign.campaign_type.value}:"
            f"{campaign.status.value}"
        )
        metadata: dict[str, str] = {
            "status": campaign.status.value,
            "campaign_type": campaign.campaign_type.value,
            "policy_id": str(campaign.policy_id),
            "organization_id": str(campaign.organization_id),
        }
        if campaign.metrics:
            metadata["total_findings"] = str(campaign.metrics.total_findings)
            metadata["success_rate"] = str(round(campaign.metrics.success_rate, 4))

        self._graph.add_node(GraphNode(
            node_id=str(campaign.id),
            node_type=NodeType.CAMPAIGN,
            label=label,
            metadata=metadata,
        ))
        added += 1

        for target_id in campaign.target_ids:
            tid_str = str(target_id)
            # Ensure the target node exists before adding the edge. In a real
            # deployment the AI_TARGET node is projected when the target is
            # created; in tests or when projecting a campaign in isolation the
            # node may be absent. We add a stub rather than raising.
            if not self._graph.get_node(tid_str):
                self._graph.add_node(GraphNode(
                    node_id=tid_str,
                    node_type=NodeType.AI_TARGET,
                    label=f"AITarget:{tid_str[:8]}",
                ))
            self._graph.add_edge(GraphEdge(
                source_id=str(campaign.id),
                target_id=tid_str,
                relationship=RelationshipType.CAMPAIGN_COVERS_TARGET,
            ))

        if (
            campaign.drift_summary is not None
            and campaign.drift_summary.regression_detected
            and campaign.baseline_campaign_id is not None
        ):
            baseline_str = str(campaign.baseline_campaign_id)
            if not self._graph.get_node(baseline_str):
                self._graph.add_node(GraphNode(
                    node_id=baseline_str,
                    node_type=NodeType.CAMPAIGN,
                    label=f"Campaign:baseline:{baseline_str[:8]}",
                ))
            self._graph.add_edge(GraphEdge(
                source_id=str(campaign.id),
                target_id=baseline_str,
                relationship=RelationshipType.CAMPAIGN_REGRESSED_FROM,
                metadata={
                    "new_findings": str(campaign.drift_summary.new_findings_count),
                    "rate_delta": str(campaign.drift_summary.vulnerability_rate_delta),
                },
            ))

        return added
