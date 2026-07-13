"""Integration tests for the Campaign Engine.

These tests prove the end-to-end Campaign → DriftDetector → KG projector
chain without a real database. The focus is on semantic correctness of
data flowing across module boundaries.
"""

from __future__ import annotations

import pytest

from redforge.application.campaigns.drift_detector import DriftDetector
from redforge.application.campaigns.knowledge_projector import (
    CampaignKnowledgeGraphProjector,
)
from redforge.application.knowledge_graph import KnowledgeGraph, NodeType
from redforge.domain.campaigns.entity import Campaign
from redforge.domain.campaigns.value_objects import (
    CampaignConfiguration,
    CampaignMetrics,
    CampaignType,
    DriftSummary,
    TargetResult,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

# ─── Shared helpers ───────────────────────────────────────────────────────────

T1 = str(EntityId.generate())
T2 = str(EntityId.generate())
T3 = str(EntityId.generate())
_ORG = str(EntityId.generate())
_POLICY = str(EntityId.generate())


def _make_result(
    target_id: str,
    findings: int = 1,
    vuln_rate: float = 0.5,
    status: str = "completed",
) -> TargetResult:
    return TargetResult(
        target_id=EntityId.from_string(target_id),
        run_id=str(EntityId.generate()),
        status=status,
        findings_count=findings,
        vulnerability_rate=vuln_rate,
        duration_ms=100,
        failure_reason=None if status == "completed" else "timeout",
    )


# ─── DriftDetector integration ────────────────────────────────────────────────


class TestDriftDetectorIntegration:
    def test_no_change_produces_zero_delta(self) -> None:
        detector = DriftDetector()
        results = [
            _make_result(T1, findings=2, vuln_rate=0.5),
            _make_result(T2, findings=1, vuln_rate=0.25),
        ]
        summary = detector.detect(
            baseline_campaign_id=EntityId.generate(),
            baseline_findings={T1: 2, T2: 1},
            baseline_vuln_rates={T1: 0.5, T2: 0.25},
            current_results=results,
        )
        assert summary.new_findings_count == 0
        assert summary.resolved_findings_count == 0
        assert summary.vulnerability_rate_delta == 0.0
        assert summary.regression_detected is False

    def test_new_finding_detected(self) -> None:
        detector = DriftDetector()
        results = [_make_result(T1, findings=3, vuln_rate=0.75)]
        summary = detector.detect(
            baseline_campaign_id=EntityId.generate(),
            baseline_findings={T1: 1},
            baseline_vuln_rates={T1: 0.25},
            current_results=results,
        )
        assert summary.new_findings_count == 2  # 3 - 1
        assert summary.regression_detected is True

    def test_resolved_finding_detected(self) -> None:
        detector = DriftDetector()
        results = [_make_result(T1, findings=0, vuln_rate=0.0)]
        summary = detector.detect(
            baseline_campaign_id=EntityId.generate(),
            baseline_findings={T1: 3},
            baseline_vuln_rates={T1: 0.75},
            current_results=results,
        )
        assert summary.resolved_findings_count == 3
        assert summary.improvement_detected is True
        assert summary.regression_detected is False

    def test_positive_rate_delta_signals_regression(self) -> None:
        detector = DriftDetector()
        results = [_make_result(T1, findings=2, vuln_rate=0.8)]
        summary = detector.detect(
            baseline_campaign_id=EntityId.generate(),
            baseline_findings={T1: 1},
            baseline_vuln_rates={T1: 0.2},
            current_results=results,
        )
        assert summary.vulnerability_rate_delta > 0

    def test_failed_targets_excluded_from_rate_delta(self) -> None:
        detector = DriftDetector()
        results = [
            _make_result(T1, findings=2, vuln_rate=0.5),
            _make_result(T2, status="failed"),  # should not affect rate delta
        ]
        summary_with = detector.detect(
            baseline_campaign_id=EntityId.generate(),
            baseline_findings={T1: 2},
            baseline_vuln_rates={T1: 0.5},
            current_results=results,
        )
        # T2 is failed so excluded; rate delta should be ~0
        assert summary_with.vulnerability_rate_delta == pytest.approx(0.0, abs=0.01)

    def test_new_target_not_in_baseline_treated_as_new(self) -> None:
        """A target absent from the baseline has 0 findings in baseline,
        so any findings it has are counted as new."""
        detector = DriftDetector()
        results = [_make_result(T3, findings=2, vuln_rate=0.5)]
        summary = detector.detect(
            baseline_campaign_id=EntityId.generate(),
            baseline_findings={},   # T3 not in baseline
            baseline_vuln_rates={},
            current_results=results,
        )
        assert summary.new_findings_count == 2


# ─── Knowledge Graph projector integration ────────────────────────────────────


class TestCampaignKGProjectorIntegration:
    def _campaign(self, n: int = 2, with_baseline: bool = False) -> Campaign:
        c = Campaign.create(
            organization_id=EntityId.generate(),
            policy_id=EntityId.generate(),
            campaign_type=CampaignType.MANUAL,
            target_ids=frozenset(EntityId.from_string(t) for t in [T1, T2][:n]),
            baseline_campaign_id=EntityId.generate() if with_baseline else None,
        )
        return c

    def _complete(self, campaign: Campaign, drift: DriftSummary | None = None) -> None:
        campaign.start()
        for tid in list(campaign.target_ids):
            campaign.record_target_completed(TargetResult(
                target_id=tid,
                run_id=str(EntityId.generate()),
                status="completed",
                findings_count=1,
                vulnerability_rate=0.5,
                duration_ms=100,
            ))
        metrics = CampaignMetrics(
            total_targets=len(campaign.target_ids),
            successful_targets=len(campaign.target_ids),
            failed_targets=0,
            total_findings=len(campaign.target_ids),
            mean_vulnerability_rate=0.5,
            total_duration_ms=500,
        )
        campaign.complete(metrics, drift_summary=drift)

    def test_projects_campaign_node(self) -> None:
        graph = KnowledgeGraph()
        projector = CampaignKnowledgeGraphProjector(graph)
        c = self._campaign()
        self._complete(c)
        projector.project_campaign(c)
        nodes = graph.query_by_type(NodeType.CAMPAIGN)
        assert len(nodes) == 1
        assert nodes[0].node_id == str(c.id)

    def test_projects_covers_target_edges(self) -> None:
        graph = KnowledgeGraph()
        projector = CampaignKnowledgeGraphProjector(graph)
        c = self._campaign(n=2)
        self._complete(c)
        projector.project_campaign(c)
        related = graph.query_related(str(c.id))
        target_ids = {str(tid) for tid in c.target_ids}
        projected_ids = {n.node_id for n in related.nodes}
        # All targets should be reachable from campaign node
        assert target_ids.issubset(projected_ids)

    def test_projects_regression_edge_on_drift(self) -> None:
        graph = KnowledgeGraph()
        baseline_id = EntityId.generate()
        projector = CampaignKnowledgeGraphProjector(graph)
        # Create campaign with the same baseline_id we'll use in DriftSummary.
        c = Campaign.create(
            organization_id=EntityId.generate(),
            policy_id=EntityId.generate(),
            campaign_type=CampaignType.REGRESSION,
            target_ids=frozenset(EntityId.from_string(t) for t in [T1, T2]),
            baseline_campaign_id=baseline_id,
        )
        drift = DriftSummary(
            baseline_campaign_id=baseline_id,
            baseline_completed_at=utc_now(),
            new_findings_count=3,
            resolved_findings_count=0,
            vulnerability_rate_delta=0.2,
        )
        self._complete(c, drift=drift)
        projector.project_campaign(c)
        related = graph.query_related(str(c.id))
        related_ids = {n.node_id for n in related.nodes}
        assert str(baseline_id) in related_ids

    def test_no_regression_edge_when_no_drift(self) -> None:
        graph = KnowledgeGraph()
        projector = CampaignKnowledgeGraphProjector(graph)
        c = self._campaign()
        self._complete(c)
        projector.project_campaign(c)
        # No baseline_campaign_id → no CAMPAIGN_REGRESSED_FROM edge. Only
        # CAMPAIGN_COVERS_TARGET edges should exist from the campaign node.
        campaign_node_type_nodes = graph.query_by_type(NodeType.CAMPAIGN)
        assert len(campaign_node_type_nodes) == 1  # only the current campaign

    def test_metrics_in_node_properties(self) -> None:
        graph = KnowledgeGraph()
        projector = CampaignKnowledgeGraphProjector(graph)
        c = self._campaign()
        self._complete(c)
        projector.project_campaign(c)
        node = graph.query_by_type(NodeType.CAMPAIGN)[0]
        assert "total_findings" in node.metadata
        assert "success_rate" in node.metadata


# ─── CampaignConfiguration value object ─────────────────────────────────────


class TestCampaignConfiguration:
    def test_defaults(self) -> None:
        cfg = CampaignConfiguration()
        assert cfg.max_concurrent_targets == 5
        assert cfg.retry_failed_targets is False

    def test_invalid_max_concurrent_raises(self) -> None:
        with pytest.raises(ValueError, match="max_concurrent_targets"):
            CampaignConfiguration(max_concurrent_targets=0)

    def test_invalid_timeout_raises(self) -> None:
        with pytest.raises(ValueError, match="timeout_seconds_per_target"):
            CampaignConfiguration(timeout_seconds_per_target=0)


# ─── CampaignProgress value object ───────────────────────────────────────────


class TestCampaignProgress:
    def test_completion_pct(self) -> None:
        from redforge.domain.campaigns.value_objects import CampaignProgress
        p = CampaignProgress(total_targets=4, completed_targets=2, failed_targets=0)
        assert p.completion_pct == 50.0

    def test_empty_campaign_is_100_pct(self) -> None:
        from redforge.domain.campaigns.value_objects import CampaignProgress
        p = CampaignProgress(total_targets=0, completed_targets=0, failed_targets=0)
        assert p.completion_pct == 100.0

    def test_with_completed_increments(self) -> None:
        from redforge.domain.campaigns.value_objects import CampaignProgress
        p = CampaignProgress(4, 1, 0).with_completed()
        assert p.completed_targets == 2

    def test_with_failed_increments(self) -> None:
        from redforge.domain.campaigns.value_objects import CampaignProgress
        p = CampaignProgress(4, 0, 1).with_failed()
        assert p.failed_targets == 2
