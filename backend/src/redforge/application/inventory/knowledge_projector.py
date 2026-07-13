"""InventoryKnowledgeGraphProjector — projects inventory artifacts to the KG.

Projects AIAsset, AssetRelationship, and InventorySnapshot domain objects
into the application-layer knowledge graph. All projections are idempotent.

Projection model:
  AI_ASSET node (per asset, keyed by asset ID)
    -> APP_OWNS_AGENT -> AI_AGENT_ASSET node
    -> AGENT_USES_MODEL -> AI_MODEL node
    -> AGENT_USES_MCP -> MCP_SERVER_ASSET node
    -> RAG_USES_VECTOR_DB -> VECTOR_DATABASE node
    etc.
  INVENTORY_SNAPSHOT node
    -> SNAPSHOT_CONTAINS_ASSET -> AI_ASSET nodes (sampled, top 50)

NodeType mapping is dict-dispatched: asset_type.value -> NodeType enum.
No switch statements.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

from redforge.application.knowledge_graph import (
    GraphEdge,
    GraphNode,
    KnowledgeGraph,
    NodeType,
    RelationshipType,
)

if TYPE_CHECKING:
    from redforge.domain.inventory.entity import AIAsset
    from redforge.domain.inventory.value_objects import (
        AssetRelationship,
        InventorySnapshot,
    )

# Dict-dispatched: AssetType.value -> NodeType
_ASSET_TYPE_TO_NODE_TYPE: dict[str, NodeType] = {
    "ai_application": NodeType.AI_APPLICATION,
    "ai_agent": NodeType.AI_AGENT_ASSET,
    "ai_model": NodeType.AI_MODEL,
    "ai_provider": NodeType.AI_PROVIDER_ASSET,
    "rag_system": NodeType.RAG_SYSTEM,
    "mcp_server": NodeType.MCP_SERVER_ASSET,
    "prompt_template": NodeType.PROMPT_TEMPLATE,
    "tool_definition": NodeType.TOOL_DEFINITION,
    "memory_store": NodeType.MEMORY_STORE,
    "knowledge_base": NodeType.KNOWLEDGE_BASE,
    "embedding_model": NodeType.EMBEDDING_MODEL,
    "vector_database": NodeType.VECTOR_DATABASE,
    "ai_endpoint": NodeType.AI_ENDPOINT,
}

# Dict-dispatched: AssetRelationshipType.value -> RelationshipType
_ASSET_REL_TO_KG_REL: dict[str, RelationshipType] = {
    "app_owns_agent": RelationshipType.APP_OWNS_AGENT,
    "agent_uses_model": RelationshipType.AGENT_USES_MODEL,
    "agent_uses_tool": RelationshipType.AGENT_USES_TOOL,
    "agent_uses_mcp": RelationshipType.AGENT_USES_MCP,
    "agent_uses_memory": RelationshipType.AGENT_USES_MEMORY,
    "agent_uses_rag": RelationshipType.AGENT_USES_RAG,
    "rag_uses_vector_db": RelationshipType.RAG_USES_VECTOR_DB,
    "rag_uses_knowledge_base": RelationshipType.RAG_USES_KNOWLEDGE_BASE,
    "rag_uses_embedding_model": RelationshipType.RAG_USES_EMBEDDING_MODEL,
    "prompt_belongs_to_agent": RelationshipType.PROMPT_BELONGS_TO_AGENT,
    "provider_hosts_model": RelationshipType.PROVIDER_HOSTS_MODEL,
    "model_serves_endpoint": RelationshipType.MODEL_SERVES_ENDPOINT,
    "app_owns_policy": RelationshipType.APP_OWNS_POLICY,
    "knowledge_base_backed_by": RelationshipType.KNOWLEDGE_BASE_BACKED_BY,
    "custom": RelationshipType.CUSTOM,
}


def _safe_add_edge(kg: KnowledgeGraph, edge: GraphEdge) -> None:
    with contextlib.suppress(ValueError):
        kg.add_edge(edge)


class InventoryKnowledgeGraphProjector:
    """Projects inventory domain objects into the shared knowledge graph.

    All projections are idempotent (add_node overwrites existing node).
    Missing reference targets are silently suppressed (_safe_add_edge).
    """

    def __init__(self, kg: KnowledgeGraph) -> None:
        self._kg = kg

    def project_asset(self, asset: AIAsset) -> None:
        """Project an AIAsset as a typed graph node."""
        node_type = _ASSET_TYPE_TO_NODE_TYPE.get(
            asset.asset_type.value, NodeType.AI_APPLICATION
        )
        node_id = f"asset:{asset.id}"
        node = GraphNode(
            node_id=node_id,
            node_type=node_type,
            label=f"{asset.asset_type.value}:{asset.name[:40]}",
            metadata={
                "organization_id": str(asset.organization_id),
                "asset_type": asset.asset_type.value,
                "name": asset.name,
                "external_id": asset.external_id,
                "lifecycle_stage": asset.lifecycle_stage.value,
                "health_status": asset.health_status.value,
                "fingerprint_hash": asset.fingerprint.fingerprint_hash,
                "version_count": str(len(asset.version_history)),
                "dependency_count": str(asset.dependency_count),
                "relationship_count": str(asset.relationship_count),
                "owner_id": asset.owner.owner_id if asset.owner else "",
                "discovery_source": asset.discovery_source.value,
            },
        )
        self._kg.add_node(node)

        # Link to organization node if it exists
        _safe_add_edge(self._kg, GraphEdge(
            source_id=f"org:{asset.organization_id}",
            target_id=node_id,
            relationship=RelationshipType.ASSET_OWNED_BY_ORG,
            metadata={"organization_id": str(asset.organization_id)},
        ))

    def project_relationship(
        self,
        source_asset: AIAsset,
        relationship: AssetRelationship,
    ) -> None:
        """Project a typed AssetRelationship as a graph edge."""
        kg_rel = _ASSET_REL_TO_KG_REL.get(
            relationship.relationship_type.value, RelationshipType.CUSTOM
        )
        source_node_id = f"asset:{source_asset.id}"
        target_node_id = f"asset:{relationship.target_asset_id}"
        _safe_add_edge(self._kg, GraphEdge(
            source_id=source_node_id,
            target_id=target_node_id,
            relationship=kg_rel,
            label=relationship.label,
            metadata={
                "relationship_id": relationship.relationship_id,
                "relationship_type": relationship.relationship_type.value,
                "organization_id": str(source_asset.organization_id),
            },
        ))

    def project_snapshot(self, snapshot: InventorySnapshot) -> None:
        """Project an InventorySnapshot as a graph node."""
        node_id = f"inventory_snapshot:{snapshot.snapshot_id}"
        node = GraphNode(
            node_id=node_id,
            node_type=NodeType.INVENTORY_SNAPSHOT,
            label=f"InvSnapshot:{snapshot.snapshot_id[:8]}",
            metadata={
                "organization_id": snapshot.organization_id,
                "asset_count": str(snapshot.asset_count),
                "relationship_count": str(snapshot.relationship_count),
                "new_asset_count": str(len(snapshot.new_assets)),
                "changed_asset_count": str(len(snapshot.changed_assets)),
                "created_at_iso": snapshot.created_at_iso,
                "period_seconds": str(snapshot.period_seconds),
            },
        )
        self._kg.add_node(node)

        # Link org to snapshot
        _safe_add_edge(self._kg, GraphEdge(
            source_id=f"org:{snapshot.organization_id}",
            target_id=node_id,
            relationship=RelationshipType.ORG_HAS_INVENTORY_SNAPSHOT,
            metadata={"organization_id": snapshot.organization_id},
        ))
