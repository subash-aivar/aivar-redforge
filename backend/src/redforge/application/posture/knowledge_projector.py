"""PostureKnowledgeGraphProjector — projects posture state into the KG.

Projects ValidationSnapshot, ValidationBaseline, ValidationTrend,
ValidationRegressionDetail, DriftEvent, and SecurityPostureScore
into the application-layer knowledge graph.

Projection model:
  VALIDATION_SNAPSHOT → SNAPSHOT_TARGETS → AI_TARGET
  VALIDATION_BASELINE → BASELINE_FROM_SNAPSHOT → VALIDATION_SNAPSHOT
  REGRESSION_EVENT → REGRESSION_DETECTED_FROM → VALIDATION_BASELINE
  DRIFT_EVENT → DRIFT_FROM_BASELINE → VALIDATION_BASELINE
  VALIDATION_TREND → TREND_FOR_TARGET → AI_TARGET
  SECURITY_POSTURE → POSTURE_INCLUDES_SNAPSHOT → VALIDATION_SNAPSHOT (sampled)

All node_ids are deterministic: re-projection is idempotent (add_node
overwrites). Edges are append-only — callers must not project the same
snapshot twice.

Domain layer is never imported directly; only public properties are read.
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
    from redforge.domain.posture.entity import ValidationBaseline, ValidationSnapshot
    from redforge.domain.posture.value_objects import (
        DriftEvent,
        SecurityPostureScore,
        ValidationRegressionDetail,
        ValidationTrend,
    )


def _add(kg: KnowledgeGraph, node: GraphNode) -> None:
    kg.add_node(node)


def _link(
    kg: KnowledgeGraph,
    source_id: str,
    target_id: str,
    rel: RelationshipType,
) -> None:
    kg.add_edge(GraphEdge(source_id=source_id, target_id=target_id, relationship=rel))


class PostureKnowledgeGraphProjector:
    """Projects posture bounded-context state into the KnowledgeGraph.

    Injected into SnapshotService/BaselineService callers via post-commit hooks.
    All projections are non-fatal (wrapped in contextlib.suppress at call site).
    """

    def __init__(self, knowledge_graph: KnowledgeGraph) -> None:
        self._kg = knowledge_graph

    # ── Snapshot ──────────────────────────────────────────────────────────────

    def project_snapshot(self, snapshot: ValidationSnapshot) -> None:
        """Project a ValidationSnapshot and link it to its AI target."""
        target_node_id = snapshot.target_id
        _add(self._kg, GraphNode(
            node_id=target_node_id,
            node_type=NodeType.AI_TARGET,
            label=f"Target:{target_node_id}",
            metadata={"organization_id": snapshot.organization_id},
        ))

        snapshot_node_id = f"snapshot:{snapshot.id}"
        _add(self._kg, GraphNode(
            node_id=snapshot_node_id,
            node_type=NodeType.VALIDATION_SNAPSHOT,
            label=f"Snapshot:{snapshot.id[:8]}",
            metadata={
                "snapshot_id": snapshot.id,
                "target_id": snapshot.target_id,
                "organization_id": snapshot.organization_id,
                "run_id": snapshot.run_id,
                "vulnerability_rate": str(snapshot.vulnerability_rate),
                "total_attacks": str(snapshot.metrics.total_attacks),
                "finding_count": str(snapshot.metrics.finding_count),
                "created_at": snapshot.created_at.isoformat(),
            },
        ))

        with contextlib.suppress(Exception):
            _link(self._kg, snapshot_node_id, target_node_id, RelationshipType.SNAPSHOT_TARGETS)

    # ── Baseline ──────────────────────────────────────────────────────────────

    def project_baseline(self, baseline: ValidationBaseline) -> None:
        """Project a ValidationBaseline and link it to its origin snapshot."""
        snapshot_node_id = f"snapshot:{baseline.snapshot_id}"
        _add(self._kg, GraphNode(
            node_id=snapshot_node_id,
            node_type=NodeType.VALIDATION_SNAPSHOT,
            label=f"Snapshot:{baseline.snapshot_id[:8]}",
            metadata={"target_id": baseline.target_id},
        ))

        baseline_node_id = f"baseline:{baseline.id}"
        _add(self._kg, GraphNode(
            node_id=baseline_node_id,
            node_type=NodeType.VALIDATION_BASELINE,
            label=f"Baseline:{baseline.id[:8]}",
            metadata={
                "baseline_id": baseline.id,
                "target_id": baseline.target_id,
                "organization_id": baseline.organization_id,
                "status": str(baseline.status),
                "vulnerability_rate": str(baseline.vulnerability_rate),
                "created_at": baseline.created_at.isoformat(),
            },
        ))

        with contextlib.suppress(Exception):
            _link(
                self._kg,
                baseline_node_id,
                snapshot_node_id,
                RelationshipType.BASELINE_FROM_SNAPSHOT,
            )

    # ── Regression ────────────────────────────────────────────────────────────

    def project_regression(
        self,
        detail: ValidationRegressionDetail,
        organization_id: str,
        target_id: str,
        baseline_id: str,
    ) -> None:
        """Project a regression detection event."""
        regression_node_id = (
            f"regression:{detail.baseline_snapshot_id}:{detail.current_snapshot_id}"
        )
        _add(self._kg, GraphNode(
            node_id=regression_node_id,
            node_type=NodeType.REGRESSION_EVENT,
            label=f"Regression:{detail.severity}",
            metadata={
                "baseline_snapshot_id": detail.baseline_snapshot_id,
                "current_snapshot_id": detail.current_snapshot_id,
                "delta": str(detail.vulnerability_rate_delta),
                "severity": str(detail.severity),
                "organization_id": organization_id,
                "target_id": target_id,
            },
        ))

        baseline_node_id = f"baseline:{baseline_id}"
        _add(self._kg, GraphNode(
            node_id=baseline_node_id,
            node_type=NodeType.VALIDATION_BASELINE,
            label=f"Baseline:{baseline_id[:8]}",
            metadata={},
        ))

        with contextlib.suppress(Exception):
            _link(
                self._kg,
                regression_node_id,
                baseline_node_id,
                RelationshipType.REGRESSION_DETECTED_FROM,
            )

    # ── Drift ─────────────────────────────────────────────────────────────────

    def project_drift(
        self,
        drift: DriftEvent,
        baseline_id: str,
    ) -> None:
        """Project a drift detection event."""
        drift_node_id = (
            f"drift:{drift.source_snapshot_id}:{drift.target_snapshot_id}"
        )
        _add(self._kg, GraphNode(
            node_id=drift_node_id,
            node_type=NodeType.DRIFT_EVENT,
            label=f"Drift:{','.join(str(dt) for dt in drift.drift_types)}",
            metadata={
                "source_snapshot_id": drift.source_snapshot_id,
                "target_snapshot_id": drift.target_snapshot_id,
                "drift_types": ",".join(str(dt) for dt in drift.drift_types),
                "description": drift.description,
                "is_significant": str(drift.is_significant),
            },
        ))

        baseline_node_id = f"baseline:{baseline_id}"
        _add(self._kg, GraphNode(
            node_id=baseline_node_id,
            node_type=NodeType.VALIDATION_BASELINE,
            label=f"Baseline:{baseline_id[:8]}",
            metadata={},
        ))

        with contextlib.suppress(Exception):
            _link(
                self._kg,
                drift_node_id,
                baseline_node_id,
                RelationshipType.DRIFT_FROM_BASELINE,
            )

    # ── Trend ─────────────────────────────────────────────────────────────────

    def project_trend(
        self,
        trend: ValidationTrend,
        organization_id: str,
        target_id: str,
    ) -> None:
        """Project a computed ValidationTrend for a target."""
        from redforge.shared.timestamps import utc_now

        trend_node_id = f"trend:{organization_id}:{target_id}"
        _add(self._kg, GraphNode(
            node_id=trend_node_id,
            node_type=NodeType.VALIDATION_TREND,
            label=f"Trend:{trend.direction}",
            metadata={
                "target_id": target_id,
                "organization_id": organization_id,
                "direction": str(trend.direction),
                "delta": str(trend.delta),
                "snapshot_count": str(trend.snapshot_count),
                "std_dev": str(trend.std_dev),
                "computed_at": utc_now().isoformat(),
            },
        ))

        _add(self._kg, GraphNode(
            node_id=target_id,
            node_type=NodeType.AI_TARGET,
            label=f"Target:{target_id}",
            metadata={"organization_id": organization_id},
        ))

        with contextlib.suppress(Exception):
            _link(
                self._kg,
                trend_node_id,
                target_id,
                RelationshipType.TREND_FOR_TARGET,
            )

    # ── Posture ───────────────────────────────────────────────────────────────

    def project_posture(
        self,
        posture: SecurityPostureScore,
        organization_id: str,
        recent_snapshots: list[ValidationSnapshot],
    ) -> None:
        """Project an org-level SecurityPostureScore."""
        from redforge.shared.timestamps import utc_now

        posture_node_id = f"posture:{organization_id}"
        _add(self._kg, GraphNode(
            node_id=posture_node_id,
            node_type=NodeType.SECURITY_POSTURE,
            label=f"Posture:{posture.level}",
            metadata={
                "organization_id": organization_id,
                "level": str(posture.level),
                "mean_vulnerability_rate": str(posture.mean_vulnerability_rate),
                "targets_assessed": str(posture.targets_assessed),
                "total_findings": str(posture.total_findings),
                "critical_targets": str(posture.critical_targets),
                "trend": str(posture.trend),
                "snapshot_count": str(posture.snapshot_count),
                "computed_at": utc_now().isoformat(),
            },
        ))

        for snapshot in recent_snapshots[:10]:
            snapshot_node_id = f"snapshot:{snapshot.id}"
            _add(self._kg, GraphNode(
                node_id=snapshot_node_id,
                node_type=NodeType.VALIDATION_SNAPSHOT,
                label=f"Snapshot:{snapshot.id[:8]}",
                metadata={"target_id": snapshot.target_id},
            ))
            with contextlib.suppress(Exception):
                _link(
                    self._kg,
                    posture_node_id,
                    snapshot_node_id,
                    RelationshipType.POSTURE_INCLUDES_SNAPSHOT,
                )
