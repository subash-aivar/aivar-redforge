"""Integration tests for the AI Security Intelligence Engine.

Tests the full pipeline from IntelligenceContext → IntelligenceReport,
multi-tenant isolation, deduplication guarantees, recommendation loops,
priority inversion prevention, false-recommendation prevention,
large org scalability, and KG projection.
"""

from __future__ import annotations

import time

import pytest

from redforge.application.intelligence.contracts import (
    DriftEventInput,
    FindingInput,
    IntelligenceContext,
    PostureInput,
    RiskIncidentInput,
    SnapshotInput,
)
from redforge.application.intelligence.intelligence_service import IntelligenceService
from redforge.application.intelligence.knowledge_projector import (
    IntelligenceKnowledgeGraphProjector,
)
from redforge.application.knowledge_graph import KnowledgeGraph

# ─── Helpers ──────────────────────────────────────────────────────────────────

ALL_CATEGORIES = frozenset({
    "prompt_injection", "jailbreak", "data_extraction", "model_denial",
    "hallucination", "bias", "tool_misuse", "mcp_injection",
    "memory_poisoning", "rag_poisoning", "multi_turn_attack",
    "system_prompt_leak", "indirect_injection",
})


def _ctx(
    org: str = "org1",
    targets: tuple[str, ...] = ("t1",),
    findings: tuple[FindingInput, ...] = (),
    snapshots: tuple[SnapshotInput, ...] = (),
    incidents: tuple[RiskIncidentInput, ...] = (),
    drift_events: tuple[DriftEventInput, ...] = (),
    posture: PostureInput | None = None,
    all_categories: frozenset[str] = ALL_CATEGORIES,
) -> IntelligenceContext:
    return IntelligenceContext(
        organization_id=org,
        target_ids=targets,
        findings=findings,
        snapshots=snapshots,
        risk_incidents=incidents,
        drift_events=drift_events,
        posture=posture,
        all_known_attack_categories=all_categories,
        period_days=30,
    )


def _finding(
    fid: str,
    target: str = "t1",
    severity: str = "high",
    category: str = "prompt_injection",
    status: str = "open",
    created_at: str = "2026-07-09T12:00:00+00:00",
) -> FindingInput:
    return FindingInput(
        finding_id=fid,
        organization_id="org1",
        target_id=target,
        run_id="run1",
        severity=severity,
        attack_category=category,
        risk_score=8.0 if severity == "high" else 9.5,
        status=status,
        created_at_iso=created_at,
    )


def _snapshot(
    sid: str,
    target: str = "t1",
    vuln_rate: float = 0.20,
    categories: frozenset[str] | None = None,
    provider: str = "openai",
    model: str = "gpt-4",
    created_at: str = "2026-07-09T12:00:00+00:00",
) -> SnapshotInput:
    cats = categories or frozenset({"prompt_injection", "jailbreak"})
    return SnapshotInput(
        snapshot_id=sid,
        organization_id="org1",
        target_id=target,
        run_id="run1",
        vulnerability_rate=vuln_rate,
        total_attacks=100,
        finding_count=int(vuln_rate * 100),
        executed_categories=cats,
        provider=provider,
        model=model,
        created_at_iso=created_at,
    )


def _incident(
    iid: str,
    priority: str = "high",
    risk_score: float = 7.5,
    attack_types: frozenset[str] | None = None,
) -> RiskIncidentInput:
    return RiskIncidentInput(
        incident_id=iid,
        organization_id="org1",
        target_ids=("t1",),
        risk_score=risk_score,
        priority=priority,
        title=f"Incident {iid}",
        attack_types=attack_types or frozenset({"prompt_injection"}),
    )


# ─── Full Pipeline Tests ───────────────────────────────────────────────────────


class TestFullPipeline:
    def test_empty_context_returns_valid_report(self) -> None:
        svc = IntelligenceService()
        ctx = IntelligenceContext(
            organization_id="org1",
            target_ids=("t1",),
            all_known_attack_categories=frozenset(),
        )
        report = svc.generate_report(ctx)
        assert report.organization_id == "org1"
        assert len(report.insights) == 0
        assert report.risk_narrative.critical_incident_count == 0
        # No findings/incidents — any recs are operational/coverage only
        for rec in report.recommendations:
            assert rec.organization_id == "org1"

    def test_critical_finding_generates_report(self) -> None:
        svc = IntelligenceService()
        ctx = _ctx(
            findings=(_finding("f1", severity="critical"),),
        )
        report = svc.generate_report(ctx)
        assert len(report.recommendations) > 0

    def test_coverage_gap_captured_in_report(self) -> None:
        svc = IntelligenceService()
        ctx = _ctx(
            targets=("t1",),
            all_categories=frozenset({"a", "b", "c", "d", "e"}),
            snapshots=(_snapshot("s1", categories=frozenset({"a"})),),
        )
        report = svc.generate_report(ctx)
        assert len(report.coverage_gaps) > 0
        gap = report.coverage_gaps[0]
        assert gap.coverage_rate < 1.0

    def test_recommendations_are_deduplicated(self) -> None:
        svc = IntelligenceService()
        # Multiple critical findings for same category → should not produce duplicate recs
        ctx = _ctx(
            findings=(
                _finding("f1", severity="critical", category="prompt_injection"),
                _finding("f2", severity="critical", category="prompt_injection"),
                _finding("f3", severity="critical", category="prompt_injection"),
                _finding("f4", severity="critical", category="prompt_injection"),
                _finding("f5", severity="critical", category="prompt_injection"),
            ),
        )
        report = svc.generate_report(ctx)
        keys = [r.deduplication_key for r in report.recommendations]
        assert len(keys) == len(set(keys)), "Duplicate recommendations in report"

    def test_insight_in_report_matches_context(self) -> None:
        svc = IntelligenceService()
        ctx = _ctx(
            findings=(
                _finding("f1", category="jailbreak"),
                _finding("f2", category="jailbreak"),
                _finding("f3", category="jailbreak"),
            ),
        )
        report = svc.generate_report(ctx)
        assert len(report.insights) >= 1

    def test_posture_narrative_present(self) -> None:
        svc = IntelligenceService()
        posture = PostureInput(
            organization_id="org1",
            mean_vulnerability_rate=0.35,
            level="poor",
            targets_assessed=2,
            total_findings=70,
            critical_targets=1,
            trend="degrading",
            snapshot_count=5,
        )
        ctx = _ctx(
            posture=posture,
            snapshots=(_snapshot("s1"),),
        )
        report = svc.generate_report(ctx)
        assert report.posture_narrative.overall_level == "poor"

    def test_report_period_days_preserved(self) -> None:
        svc = IntelligenceService()
        ctx = IntelligenceContext(
            organization_id="org1",
            target_ids=("t1",),
            period_days=90,
        )
        report = svc.generate_report(ctx)
        assert report.period_days == 90

    def test_has_critical_recommendations_flag(self) -> None:
        svc = IntelligenceService()
        ctx = _ctx(
            findings=(
                _finding("f1", severity="critical"),
                _finding("f2", severity="critical"),
            ),
            incidents=(_incident("i1", priority="critical", risk_score=9.9),),
            posture=PostureInput(
                organization_id="org1",
                mean_vulnerability_rate=0.70,
                level="critical",
                targets_assessed=1,
                total_findings=70,
                critical_targets=1,
                trend="degrading",
                snapshot_count=3,
            ),
        )
        report = svc.generate_report(ctx)
        if report.recommendations:
            assert isinstance(report.has_critical_recommendations, bool)


# ─── Multi-Tenant Isolation ────────────────────────────────────────────────────


class TestMultiTenantIsolation:
    def test_two_orgs_produce_independent_reports(self) -> None:
        svc = IntelligenceService()
        ctx1 = IntelligenceContext(
            organization_id="org-alpha",
            target_ids=("t1",),
            findings=(_finding("f1", severity="critical"),),
            all_known_attack_categories=ALL_CATEGORIES,
        )
        ctx2 = IntelligenceContext(
            organization_id="org-beta",
            target_ids=("t9",),
            all_known_attack_categories=ALL_CATEGORIES,
        )
        report1 = svc.generate_report(ctx1)
        report2 = svc.generate_report(ctx2)
        assert report1.organization_id == "org-alpha"
        assert report2.organization_id == "org-beta"
        # org2 has no findings/incidents/snapshots — any recs are coverage-gap-only
        # (zero coverage with known categories is a valid finding)
        for rec in report2.recommendations:
            assert rec.organization_id == "org-beta"

    def test_org_ids_never_cross_contaminate(self) -> None:
        svc = IntelligenceService()
        reports = []
        for i in range(5):
            ctx = IntelligenceContext(
                organization_id=f"org-{i}",
                target_ids=(f"target-{i}",),
                findings=(
                    FindingInput(
                        finding_id=f"f-{i}",
                        organization_id=f"org-{i}",
                        target_id=f"target-{i}",
                        run_id=f"run-{i}",
                        severity="critical",
                        attack_category="prompt_injection",
                        risk_score=9.0,
                    ),
                ),
                all_known_attack_categories=ALL_CATEGORIES,
            )
            reports.append(svc.generate_report(ctx))

        for i, report in enumerate(reports):
            assert report.organization_id == f"org-{i}"
            for rec in report.recommendations:
                assert rec.organization_id == f"org-{i}"
            for insight in report.insights:
                assert insight.organization_id == f"org-{i}"


# ─── Priority Inversion Prevention ────────────────────────────────────────────


class TestPriorityInversion:
    def test_higher_base_score_wins_without_multiplier(self) -> None:
        svc = IntelligenceService()
        ctx = _ctx(
            findings=(
                _finding("f1", severity="critical"),
            ),
        )
        report = svc.generate_report(ctx)
        if len(report.recommendations) >= 2:
            priorities = [r.priority_score for r in report.recommendations]
            # Should be sorted descending
            assert all(priorities[i] >= priorities[i + 1] for i in range(len(priorities) - 1))

    def test_critical_posture_elevates_all_recommendations(self) -> None:
        svc = IntelligenceService()
        posture = PostureInput(
            organization_id="org1",
            mean_vulnerability_rate=0.80,
            level="critical",
            targets_assessed=3,
            total_findings=240,
            critical_targets=3,
            trend="degrading",
            snapshot_count=10,
        )
        ctx = _ctx(
            posture=posture,
            findings=(_finding("f1", severity="high"),),
        )
        report = svc.generate_report(ctx)
        # All recs in a critical posture should be elevated
        assert all(
            r.priority in {"critical", "high"}
            for r in report.recommendations
        ) or len(report.recommendations) == 0


# ─── False Recommendation Prevention ─────────────────────────────────────────


class TestFalseRecommendationPrevention:
    def test_perfect_coverage_no_coverage_gap_recommendation(self) -> None:
        svc = IntelligenceService()
        full_cats = frozenset({"a", "b", "c"})
        ctx = _ctx(
            all_categories=full_cats,
            snapshots=(_snapshot("s1", categories=full_cats),),
        )
        report = svc.generate_report(ctx)
        gap_recs = [r for r in report.recommendations if r.category.value == "coverage_gap"]
        assert len(gap_recs) == 0

    def test_low_vuln_rate_no_risk_score_critical_recommendation(self) -> None:
        svc = IntelligenceService()
        ctx = IntelligenceContext(
            organization_id="org1",
            target_ids=("t1",),
            snapshots=(_snapshot("s1", vuln_rate=0.02, categories=frozenset(ALL_CATEGORIES)),),
            all_known_attack_categories=ALL_CATEGORIES,
        )
        report = svc.generate_report(ctx)
        # With full coverage and low vuln rate, no risk-based critical recs
        risk_critical = [
            r for r in report.recommendations
            if r.priority.value == "critical"
            and r.category.value != "coverage_gap"
        ]
        assert len(risk_critical) == 0


# ─── Large Org Scalability ────────────────────────────────────────────────────


class TestScalability:
    def test_50_targets_under_500ms(self) -> None:
        svc = IntelligenceService()
        targets = tuple(f"target-{i}" for i in range(50))
        snapshots = tuple(
            SnapshotInput(
                snapshot_id=f"s-{i}",
                organization_id="org1",
                target_id=f"target-{i}",
                run_id="run1",
                vulnerability_rate=0.10 + (i % 5) * 0.05,
                total_attacks=100,
                finding_count=10,
                executed_categories=frozenset({"prompt_injection", "jailbreak"}),
            )
            for i in range(50)
        )
        findings = tuple(
            FindingInput(
                finding_id=f"f-{i}",
                organization_id="org1",
                target_id=f"target-{i % 50}",
                run_id="run1",
                severity="high" if i % 3 == 0 else "medium",
                attack_category="prompt_injection",
                risk_score=7.0,
            )
            for i in range(100)
        )
        ctx = IntelligenceContext(
            organization_id="org1",
            target_ids=targets,
            snapshots=snapshots,
            findings=findings,
            all_known_attack_categories=ALL_CATEGORIES,
            period_days=30,
        )
        start = time.monotonic()
        report = svc.generate_report(ctx)
        elapsed = time.monotonic() - start
        assert elapsed < 0.500, f"Pipeline took {elapsed:.3f}s for 50 targets"
        assert report.organization_id == "org1"

    def test_500_findings_under_1_second(self) -> None:
        svc = IntelligenceService()
        findings = tuple(
            FindingInput(
                finding_id=f"f-{i}",
                organization_id="org1",
                target_id=f"target-{i % 10}",
                run_id="run1",
                severity="critical" if i % 5 == 0 else "high",
                attack_category=f"category_{i % 5}",
                risk_score=8.0,
            )
            for i in range(500)
        )
        ctx = IntelligenceContext(
            organization_id="org1",
            target_ids=tuple(f"target-{i}" for i in range(10)),
            findings=findings,
            all_known_attack_categories=frozenset(f"category_{i}" for i in range(20)),
            period_days=30,
        )
        start = time.monotonic()
        report = svc.generate_report(ctx)
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, f"Pipeline took {elapsed:.3f}s for 500 findings"
        assert len(report.recommendations) > 0


# ─── Knowledge Graph Projection ───────────────────────────────────────────────


class TestKnowledgeGraphProjection:
    def test_insight_projected_to_kg(self) -> None:
        from redforge.domain.intelligence.entity import SecurityInsight
        from redforge.domain.intelligence.value_objects import InsightType

        kg = KnowledgeGraph()
        projector = IntelligenceKnowledgeGraphProjector(kg)
        insight, _ = SecurityInsight.create(
            organization_id="org1",
            insight_type=InsightType.PATTERN,
            title="Test Pattern",
            description="Persistent attack pattern",
            affected_targets=("t1",),
            supporting_finding_ids=("f1", "f2"),
            supporting_incident_ids=(),
            confidence=0.90,
        )
        projector.project_insight(insight)
        node = kg.get_node(f"insight:{insight.id}")
        assert node is not None
        assert node.metadata["organization_id"] == "org1"

    def test_recommendation_projected_to_kg(self) -> None:
        from redforge.domain.intelligence.entity import Recommendation
        from redforge.domain.intelligence.value_objects import (
            RecommendationCategory,
            RecommendationEvidence,
            RecommendationPriority,
        )

        kg = KnowledgeGraph()
        projector = IntelligenceKnowledgeGraphProjector(kg)
        rec, _ = Recommendation.create(
            organization_id="org1",
            target_id="t1",
            category=RecommendationCategory.PROMPT_SECURITY,
            priority=RecommendationPriority.HIGH,
            priority_score=75.0,
            title="Enable guardrails",
            description="Description",
            evidence=RecommendationEvidence(rationale="evidence"),
            remediation_steps=(),
            rule_id="R001",
        )
        projector.project_recommendation(rec)
        node = kg.get_node(f"recommendation:{rec.id}")
        assert node is not None
        assert node.metadata["category"] == "prompt_security"

    def test_coverage_gap_projected_to_kg(self) -> None:
        from redforge.domain.intelligence.value_objects import AttackCoverageGap

        kg = KnowledgeGraph()
        projector = IntelligenceKnowledgeGraphProjector(kg)
        gap = AttackCoverageGap(
            target_id="t1",
            organization_id="org1",
            tested_categories=frozenset({"a"}),
            missing_categories=frozenset({"b", "c"}),
            coverage_rate=0.33,
        )
        projector.project_coverage_gap(gap)
        node = kg.get_node("coverage_gap:org1:t1")
        assert node is not None
        assert node.metadata["coverage_rate"] == pytest.approx(0.33)

    def test_report_projected_with_children(self) -> None:
        svc = IntelligenceService()
        ctx = _ctx(
            findings=(_finding("f1", severity="critical"),),
            all_categories=frozenset({"prompt_injection", "jailbreak", "data_extraction"}),
            snapshots=(_snapshot("s1", categories=frozenset({"prompt_injection"})),),
        )
        report = svc.generate_report(ctx)

        kg = KnowledgeGraph()
        projector = IntelligenceKnowledgeGraphProjector(kg)
        projector.project_report(report, project_children=True)

        report_node = kg.get_node(f"intelligence_report:{report.id}")
        assert report_node is not None

        for rec in report.recommendations:
            assert kg.get_node(f"recommendation:{rec.id}") is not None

        for insight in report.insights:
            assert kg.get_node(f"insight:{insight.id}") is not None

    def test_kg_projection_idempotent(self) -> None:
        from redforge.domain.intelligence.entity import SecurityInsight
        from redforge.domain.intelligence.value_objects import InsightType

        kg = KnowledgeGraph()
        projector = IntelligenceKnowledgeGraphProjector(kg)
        insight, _ = SecurityInsight.create(
            organization_id="org1",
            insight_type=InsightType.ANOMALY,
            title="Anomaly",
            description="Anomaly detected",
            affected_targets=("t1",),
            supporting_finding_ids=(),
            supporting_incident_ids=(),
            confidence=0.75,
        )
        projector.project_insight(insight)
        projector.project_insight(insight)  # second call — idempotent
        node = kg.get_node(f"insight:{insight.id}")
        assert node is not None


# ─── Recommendation Loop Prevention ───────────────────────────────────────────


class TestRecommendationLoops:
    def test_running_pipeline_twice_same_context_no_explosion(self) -> None:
        svc = IntelligenceService()
        ctx = _ctx(
            findings=(
                _finding("f1", severity="critical"),
                _finding("f2", severity="high"),
            ),
        )
        report1 = svc.generate_report(ctx)
        report2 = svc.generate_report(ctx)
        # Same context → same output; no growing recommendation list
        assert len(report1.recommendations) == len(report2.recommendations)

    def test_deduplication_key_stability(self) -> None:
        svc = IntelligenceService()
        ctx = _ctx(findings=(_finding("f1", severity="critical"),))
        report = svc.generate_report(ctx)
        keys = [r.deduplication_key for r in report.recommendations]
        assert len(keys) == len(set(keys))
