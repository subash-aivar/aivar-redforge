"""Knowledge Graph Populator — wires validation outputs into the Knowledge Graph.

Called AFTER a successful UnitOfWork commit. Consumes:
  - ValidationRun (domain entity)
  - Evidence list (domain entities)
  - Finding list (domain entities)
  - RiskIncident list (application DTOs)
  - ValidationServiceRequest (target/provider metadata)

Adds nodes and edges that express the full security narrative:
  Organization → Target → Provider → Attack → Evidence → Finding → RiskIncident

This module is stateless. It only calls KnowledgeGraph.add_node() and
KnowledgeGraph.add_edge() — never reads from the graph.

Architecture note: lives in Application layer. Zero domain imports beyond
reading entity IDs and attributes. No infrastructure dependencies.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from redforge.application.knowledge_graph import (
    GraphEdge,
    GraphNode,
    KnowledgeGraph,
    NodeType,
    RelationshipType,
)

if TYPE_CHECKING:
    from redforge.application.risk_engine import RiskIncident
    from redforge.domain.evidence.entity import Evidence
    from redforge.domain.findings.entity import Finding
    from redforge.domain.validations.entity import ValidationRun


class KnowledgeGraphPopulator:
    """Populates the Knowledge Graph after a completed validation run.

    Thread-safe: only appends nodes/edges, never reads or deletes.
    Idempotent: adding the same node twice is a no-op (graph deduplicates by key).
    """

    def __init__(self, graph: KnowledgeGraph) -> None:
        self._graph = graph

    def populate(
        self,
        run: ValidationRun,
        evidence_list: list[Evidence],
        finding_list: list[Finding],
        risk_incidents: list[RiskIncident],
        organization_id: str,
        target_id: str,
        target_name: str,
        target_provider: str,
        model: str,
        scenario_id: str | None = None,
    ) -> int:
        """Populate graph nodes and edges from a completed validation run.

        Returns:
            Number of nodes added to the graph.
        """
        nodes_added = 0

        # ── Organization node ──────────────────────────────────────────────
        org_node = GraphNode(
            node_id=organization_id,
            node_type=NodeType.ORGANIZATION,
            label=f"Organization {organization_id[:8]}",
            metadata={"organization_id": organization_id},
        )
        self._graph.add_node(org_node)
        nodes_added += 1

        # ── AI Target node ─────────────────────────────────────────────────
        target_node = GraphNode(
            node_id=target_id,
            node_type=NodeType.AI_TARGET,
            label=target_name,
            metadata={
                "target_id": target_id,
                "provider": target_provider,
                "model": model,
            },
        )
        self._graph.add_node(target_node)
        nodes_added += 1

        # ── Provider node ──────────────────────────────────────────────────
        provider_node = GraphNode(
            node_id=f"provider:{target_provider}",
            node_type=NodeType.PROVIDER,
            label=target_provider.title(),
            metadata={"provider": target_provider},
        )
        self._graph.add_node(provider_node)
        nodes_added += 1

        # Org → Target
        self._graph.add_edge(GraphEdge(
            source_id=organization_id,
            target_id=target_id,
            relationship=RelationshipType.CUSTOM,
            label="owns_target",
        ))

        # Target → Provider
        self._graph.add_edge(GraphEdge(
            source_id=target_id,
            target_id=f"provider:{target_provider}",
            relationship=RelationshipType.TARGET_USES_PROVIDER,
            label="uses_provider",
        ))

        # ── ValidationRun node ─────────────────────────────────────────────
        run_id = str(run.id)
        run_node = GraphNode(
            node_id=run_id,
            node_type=NodeType.CUSTOM,
            label=f"Validation Run {run_id[:8]}",
            metadata={
                "run_id": run_id,
                "status": str(run.status),
                "trigger_type": str(run.trigger_type),
                "scenario_id": scenario_id or "",
            },
        )
        self._graph.add_node(run_node)
        nodes_added += 1

        # Target → Run
        self._graph.add_edge(GraphEdge(
            source_id=target_id,
            target_id=run_id,
            relationship=RelationshipType.CUSTOM,
            label="validated_by",
        ))

        # ── Evidence nodes ─────────────────────────────────────────────────
        attack_node_ids: set[str] = set()
        for evidence in evidence_list:
            ev_id = str(evidence.id)

            # Deduplicate attack definition nodes across evidence
            attack_node_id = f"attack:{evidence.attack_ref.attack_id}"
            if attack_node_id not in attack_node_ids:
                attack_node = GraphNode(
                    node_id=attack_node_id,
                    node_type=NodeType.ATTACK_DEFINITION,
                    label=evidence.attack_ref.attack_name.replace("_", " ").title(),
                    metadata={
                        "attack_id": evidence.attack_ref.attack_id,
                        "attack_name": evidence.attack_ref.attack_name,
                        "attack_type": evidence.attack_ref.attack_type,
                        "category": evidence.test_case_ref.category,
                    },
                )
                self._graph.add_node(attack_node)
                attack_node_ids.add(attack_node_id)
                nodes_added += 1

            # Evidence node
            evidence_node = GraphNode(
                node_id=ev_id,
                node_type=NodeType.EVIDENCE,
                label=f"Evidence {ev_id[:8]}",
                metadata={
                    "evidence_id": ev_id,
                    "result": str(evidence.result),
                    "confidence": evidence.confidence.score,
                    "attack_name": evidence.attack_ref.attack_name,
                    "category": evidence.test_case_ref.category,
                    "finalized": evidence.is_finalized,
                },
            )
            self._graph.add_node(evidence_node)
            nodes_added += 1

            # Attack → Evidence
            self._graph.add_edge(GraphEdge(
                source_id=attack_node_id,
                target_id=ev_id,
                relationship=RelationshipType.ATTACK_GENERATES_EVIDENCE,
                weight=evidence.confidence.score,
            ))

            # Run → Evidence
            self._graph.add_edge(GraphEdge(
                source_id=run_id,
                target_id=ev_id,
                relationship=RelationshipType.CUSTOM,
                label="produced_evidence",
            ))

        # ── Finding nodes ──────────────────────────────────────────────────
        for finding in finding_list:
            f_id = str(finding.id)

            finding_node = GraphNode(
                node_id=f_id,
                node_type=NodeType.FINDING,
                label=finding.title,
                metadata={
                    "finding_id": f_id,
                    "severity": str(finding.severity),
                    "risk_score": finding.risk_score.score,
                    "status": str(finding.status),
                    "evidence_count": len(finding.evidence_ids),
                },
            )
            self._graph.add_node(finding_node)
            nodes_added += 1

            # Evidence → Finding
            for eid in finding.evidence_ids:
                self._graph.add_edge(GraphEdge(
                    source_id=str(eid),
                    target_id=f_id,
                    relationship=RelationshipType.EVIDENCE_GENERATES_FINDING,
                    weight=finding.risk_score.score / 10.0,
                ))

            # Run → Finding
            self._graph.add_edge(GraphEdge(
                source_id=run_id,
                target_id=f_id,
                relationship=RelationshipType.VALIDATION_CREATED_FINDING,
            ))

        # ── Risk Incident nodes ────────────────────────────────────────────
        for incident in risk_incidents:
            inc_node = GraphNode(
                node_id=incident.incident_id,
                node_type=NodeType.RISK_INCIDENT,
                label=incident.title,
                metadata=_incident_metadata(incident),
            )
            self._graph.add_node(inc_node)
            nodes_added += 1

            # Finding → RiskIncident
            for fid in incident.finding_ids:
                self._graph.add_edge(GraphEdge(
                    source_id=fid,
                    target_id=incident.incident_id,
                    relationship=RelationshipType.FINDING_INCREASES_RISK,
                    weight=incident.risk_score.overall / 10.0,
                ))

        return nodes_added


def _incident_metadata(incident: RiskIncident) -> dict[str, Any]:
    return {
        "incident_id": incident.incident_id,
        "risk_score": incident.risk_score.overall,
        "priority": str(incident.priority),
        "status": str(incident.status),
        "affected_targets": incident.affected_targets,
        "finding_count": len(incident.finding_ids),
        "executive_summary": incident.executive_summary[:200],
    }
