"""IntelligenceKnowledgeGraphProjector — projects intelligence artifacts to the KG.

The knowledge graph is a projection target only. This projector converts
SecurityInsight, Recommendation, IntelligenceReport, and CoverageGap domain
objects into graph nodes and edges. Call after persisting domain objects.
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
    from redforge.domain.intelligence.entity import (
        IntelligenceReport,
        Recommendation,
        SecurityInsight,
    )
    from redforge.domain.intelligence.value_objects import AttackCoverageGap


class IntelligenceKnowledgeGraphProjector:
    """Projects intelligence domain objects into the shared knowledge graph.

    All methods are idempotent — re-projecting the same object is safe.
    """

    def __init__(self, kg: KnowledgeGraph) -> None:
        self._kg = kg

    def project_insight(self, insight: SecurityInsight) -> None:
        """Project a SecurityInsight node and its edges to supporting findings."""
        node = GraphNode(
            node_id=f"insight:{insight.id}",
            node_type=NodeType.INSIGHT,
            label=f"Insight:{insight.id[:8]}",
            metadata={
                "organization_id": insight.organization_id,
                "insight_type": insight.insight_type.value,
                "title": insight.title,
                "confidence": insight.confidence,
                "affected_target_count": len(insight.affected_targets),
                "finding_count": len(insight.supporting_finding_ids),
            },
        )
        self._kg.add_node(node)

        for finding_id in insight.supporting_finding_ids:
            _safe_add_edge(self._kg,
                GraphEdge(
                    source_id=f"insight:{insight.id}",
                    target_id=f"finding:{finding_id}",
                    relationship=RelationshipType.INSIGHT_FROM_FINDING,
                    metadata={"org": insight.organization_id},
                )
            )

    def project_recommendation(self, rec: Recommendation) -> None:
        """Project a Recommendation node with edges to insight and target."""
        node = GraphNode(
            node_id=f"recommendation:{rec.id}",
            node_type=NodeType.RECOMMENDATION,
            label=f"Recommendation:{rec.id[:8]}",
            metadata={
                "organization_id": rec.organization_id,
                "target_id": rec.target_id,
                "category": rec.category.value,
                "priority": rec.priority.value,
                "priority_score": rec.priority_score,
                "status": rec.status.value,
                "rule_id": rec.rule_id,
                "title": rec.title,
            },
        )
        self._kg.add_node(node)

        # Edge: recommendation → its target (if target-scoped)
        if rec.target_id:
            _safe_add_edge(self._kg,
                GraphEdge(
                    source_id=f"recommendation:{rec.id}",
                    target_id=f"target:{rec.target_id}",
                    relationship=RelationshipType.RECOMMENDATION_TARGETS,
                    metadata={"org": rec.organization_id},
                )
            )

        # Edge: recommendation → supporting insights (via evidence)
        for insight_id in rec.evidence.insight_ids:
            _safe_add_edge(self._kg,
                GraphEdge(
                    source_id=f"recommendation:{rec.id}",
                    target_id=f"insight:{insight_id}",
                    relationship=RelationshipType.RECOMMENDATION_FROM_INSIGHT,
                    metadata={"org": rec.organization_id},
                )
            )

    def project_coverage_gap(self, gap: AttackCoverageGap) -> None:
        """Project an AttackCoverageGap node and its edge to the target."""
        node_id = f"coverage_gap:{gap.organization_id}:{gap.target_id}"
        node = GraphNode(
            node_id=node_id,
            node_type=NodeType.COVERAGE_GAP,
            label=f"CoverageGap:{gap.target_id[:12]}",
            metadata={
                "organization_id": gap.organization_id,
                "target_id": gap.target_id,
                "coverage_rate": gap.coverage_rate,
                "tested_category_count": len(gap.tested_categories),
                "missing_category_count": len(gap.missing_categories),
                "gap_severity": gap.gap_severity.value,
            },
        )
        self._kg.add_node(node)

        _safe_add_edge(self._kg,
            GraphEdge(
                source_id=node_id,
                target_id=f"target:{gap.target_id}",
                relationship=RelationshipType.COVERAGE_GAP_FOR_TARGET,
                metadata={"org": gap.organization_id},
            )
        )

    def project_report(
        self,
        report: IntelligenceReport,
        *,
        project_children: bool = False,
    ) -> None:
        """Project an IntelligenceReport node and its containment edges.

        Set project_children=True to also project all child insights,
        recommendations, and coverage gaps in one call. Useful in tests.
        """
        node = GraphNode(
            node_id=f"intelligence_report:{report.id}",
            node_type=NodeType.INTELLIGENCE_REPORT,
            label=f"IntelligenceReport:{report.id[:8]}",
            metadata={
                "organization_id": report.organization_id,
                "target_count": len(report.target_ids),
                "recommendation_count": len(report.recommendations),
                "insight_count": len(report.insights),
                "coverage_gap_count": len(report.coverage_gaps),
                "critical_recommendation_count": report.critical_recommendation_count,
                "period_days": report.period_days,
            },
        )
        self._kg.add_node(node)

        if project_children:
            for insight in report.insights:
                self.project_insight(insight)
            for rec in report.recommendations:
                self.project_recommendation(rec)
            for gap in report.coverage_gaps:
                self.project_coverage_gap(gap)

        for rec in report.recommendations:
            _safe_add_edge(self._kg,
                GraphEdge(
                    source_id=f"intelligence_report:{report.id}",
                    target_id=f"recommendation:{rec.id}",
                    relationship=RelationshipType.REPORT_INCLUDES_RECOMMENDATION,
                    metadata={"org": report.organization_id},
                )
            )

        for insight in report.insights:
            _safe_add_edge(self._kg,
                GraphEdge(
                    source_id=f"intelligence_report:{report.id}",
                    target_id=f"insight:{insight.id}",
                    relationship=RelationshipType.REPORT_INCLUDES_INSIGHT,
                    metadata={"org": report.organization_id},
                )
            )

        for gap in report.coverage_gaps:
            gap_node_id = f"coverage_gap:{gap.organization_id}:{gap.target_id}"
            _safe_add_edge(self._kg,
                GraphEdge(
                    source_id=f"intelligence_report:{report.id}",
                    target_id=gap_node_id,
                    relationship=RelationshipType.REPORT_INCLUDES_GAP,
                    metadata={"org": report.organization_id},
                )
            )


def _safe_add_edge(kg: KnowledgeGraph, edge: GraphEdge) -> None:
    """Add an edge; silently skip if source or target node is absent."""
    with contextlib.suppress(ValueError):
        kg.add_edge(edge)
