"""ConnectorKnowledgeGraphProjector — projects connector data into the KG.

Projection is idempotent: projecting the same Connector twice produces the
same graph state because add_node overwrites by node_id, and edges are
guarded against duplicates by the projector's per-call seen-set.

Projected node types (all added in Sprint 23):
  CONNECTOR            — one per Connector aggregate
  DISCOVERY_JOB        — one per DiscoveryJobRecord in connector.discovery_history
  SYNC_JOB             — one per SyncJobRecord in connector.sync_history
  EXTERNAL_PLATFORM    — one per ConnectorType (platform label node)
  CONNECTOR_HEALTH     — one per Connector (when health is known)

Relationship types:
  CONNECTOR_BELONGS_TO_ORG    — connector → org node (if org node exists)
  CONNECTOR_RAN_DISCOVERY_JOB — connector → each discovery job
  CONNECTOR_RAN_SYNC_JOB      — connector → each sync job
  CONNECTOR_USES_PLATFORM     — connector → external platform
  CONNECTOR_HEALTH_FOR        — health node → connector
"""

from __future__ import annotations

from redforge.application.knowledge_graph import (
    GraphEdge,
    GraphNode,
    KnowledgeGraph,
    NodeType,
    RelationshipType,
)
from redforge.domain.connectors.entity import Connector
from redforge.domain.connectors.value_objects import ConnectorHealthStatus


class ConnectorKnowledgeGraphProjector:
    """Projects Connector aggregates and their jobs into a KnowledgeGraph."""

    def project_connector(self, connector: Connector, graph: KnowledgeGraph) -> None:
        """Project a Connector and its full job history into the graph."""
        connector_id = str(connector.id)
        org_id = str(connector.organization_id)
        # Track edges added this call to avoid duplicates on re-projection.
        seen_edges: set[str] = set()

        def _add_edge(edge: GraphEdge) -> None:
            key = f"{edge.source_id}|{edge.relationship}|{edge.target_id}"
            if key not in seen_edges:
                seen_edges.add(key)
                graph.add_edge(edge)

        # ── CONNECTOR node ─────────────────────────────────────────────────
        graph.add_node(GraphNode(
            node_id=connector_id,
            node_type=NodeType.CONNECTOR,
            label=connector.name,
            metadata={
                "connector_type": connector.connector_type.value,
                "status": connector.status.value,
                "organization_id": org_id,
                "description": connector.description,
                "version": connector.version.connector_type_version,
            },
        ))

        # ── EXTERNAL_PLATFORM node ─────────────────────────────────────────
        platform_node_id = f"platform:{connector.connector_type.value}"
        graph.add_node(GraphNode(
            node_id=platform_node_id,
            node_type=NodeType.EXTERNAL_PLATFORM,
            label=connector.connector_type.value.replace("_", " ").title(),
            metadata={"connector_type": connector.connector_type.value},
        ))
        _add_edge(GraphEdge(
            source_id=connector_id,
            target_id=platform_node_id,
            relationship=RelationshipType.CONNECTOR_USES_PLATFORM,
            label=f"{connector.name} uses {connector.connector_type.value}",
        ))

        # ── ORG relationship (only if org node already in graph) ───────────
        org_node_id = f"org:{org_id}"
        if graph.has_node(org_node_id):
            _add_edge(GraphEdge(
                source_id=connector_id,
                target_id=org_node_id,
                relationship=RelationshipType.CONNECTOR_BELONGS_TO_ORG,
                label="belongs to org",
            ))

        # ── CONNECTOR_HEALTH node ──────────────────────────────────────────
        health = connector.health
        if health.status != ConnectorHealthStatus.UNKNOWN:
            health_node_id = f"health:{connector_id}"
            graph.add_node(GraphNode(
                node_id=health_node_id,
                node_type=NodeType.CONNECTOR_HEALTH,
                label=f"{connector.name} health",
                metadata={
                    "status": health.status.value,
                    "latency_ms": str(health.latency_ms),
                    "error_message": health.error_message,
                    "last_check_at_iso": health.last_check_at_iso,
                },
            ))
            _add_edge(GraphEdge(
                source_id=health_node_id,
                target_id=connector_id,
                relationship=RelationshipType.CONNECTOR_HEALTH_FOR,
                label="health for",
            ))

        # ── DISCOVERY_JOB nodes ────────────────────────────────────────────
        for job in connector.discovery_history:
            job_node_id = f"discovery_job:{job.job_id}"
            graph.add_node(GraphNode(
                node_id=job_node_id,
                node_type=NodeType.DISCOVERY_JOB,
                label=f"Discovery {job.job_id[:8]}",
                metadata={
                    "job_id": job.job_id,
                    "status": job.status.value,
                    "assets_discovered": str(job.assets_discovered),
                    "assets_normalized": str(job.assets_normalized),
                    "assets_failed": str(job.assets_failed),
                    "started_at_iso": job.started_at_iso,
                    "completed_at_iso": job.completed_at_iso,
                    "error_message": job.error_message,
                },
            ))
            _add_edge(GraphEdge(
                source_id=connector_id,
                target_id=job_node_id,
                relationship=RelationshipType.CONNECTOR_RAN_DISCOVERY_JOB,
                label="ran discovery job",
            ))

        # ── SYNC_JOB nodes ─────────────────────────────────────────────────
        for sjob in connector.sync_history:
            sync_node_id = f"sync_job:{sjob.job_id}"
            graph.add_node(GraphNode(
                node_id=sync_node_id,
                node_type=NodeType.SYNC_JOB,
                label=f"Sync {sjob.job_id[:8]}",
                metadata={
                    "job_id": sjob.job_id,
                    "status": sjob.status.value,
                    "is_full_sync": str(sjob.is_full_sync),
                    "assets_added": str(sjob.assets_added),
                    "assets_updated": str(sjob.assets_updated),
                    "assets_failed": str(sjob.assets_failed),
                    "started_at_iso": sjob.started_at_iso,
                    "completed_at_iso": sjob.completed_at_iso,
                    "error_message": sjob.error_message,
                },
            ))
            _add_edge(GraphEdge(
                source_id=connector_id,
                target_id=sync_node_id,
                relationship=RelationshipType.CONNECTOR_RAN_SYNC_JOB,
                label="ran sync job",
            ))

    def project_connectors(
        self, connectors: list[Connector], graph: KnowledgeGraph
    ) -> None:
        """Project multiple connectors into the graph."""
        for connector in connectors:
            self.project_connector(connector, graph)
