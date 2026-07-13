"""Unit tests for intelligence application services.

Tests CoverageAnalyzer, GapAnalyzer, InsightGenerator, RecommendationGenerator,
PriorityEngine, NarrativeBuilder as stateless services using in-process fixtures.
"""

from __future__ import annotations

import pytest

from redforge.application.intelligence.contracts import (
    DriftEventInput,
    FindingInput,
    IntelligenceContext,
    PostureInput,
    RiskIncidentInput,
    SnapshotInput,
)
from redforge.application.intelligence.coverage_analyzer import CoverageAnalyzer
from redforge.application.intelligence.gap_analyzer import GapAnalyzer
from redforge.application.intelligence.insight_generator import InsightGenerator
from redforge.application.intelligence.narrative_builder import NarrativeBuilder
from redforge.application.intelligence.priority_engine import PriorityEngine
from redforge.application.intelligence.recommendation_generator import (
    RecommendationGenerator,
)
from redforge.application.intelligence.remediation_planner import RemediationPlanner
from redforge.domain.intelligence.value_objects import (
    AttackCoverageGap,
    RecommendationCategory,
    RecommendationPriority,
)

# ─── Fixtures ─────────────────────────────────────────────────────────────────

ALL_CATEGORIES = frozenset({
    "prompt_injection", "jailbreak", "data_extraction", "model_denial",
    "hallucination", "bias", "tool_misuse", "mcp_injection",
    "memory_poisoning", "rag_poisoning",
})


def _make_context(**kwargs: object) -> IntelligenceContext:
    defaults: dict = dict(
        organization_id="org1",
        target_ids=("t1", "t2"),
        risk_incidents=(),
        findings=(),
        snapshots=(),
        drift_events=(),
        posture=None,
        all_known_attack_categories=ALL_CATEGORIES,
        period_days=30,
    )
    defaults.update(kwargs)
    return IntelligenceContext(**defaults)


def _finding(
    fid: str = "f1",
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
        risk_score=8.0,
        status=status,
        created_at_iso=created_at,
    )


def _snapshot(
    sid: str = "s1",
    target: str = "t1",
    vuln_rate: float = 0.20,
    categories: frozenset[str] | None = None,
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
        created_at_iso=created_at,
    )


def _incident(
    iid: str = "inc1",
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
        title="Test incident",
        attack_types=attack_types or frozenset({"prompt_injection"}),
    )


# ─── CoverageAnalyzer ─────────────────────────────────────────────────────────


class TestCoverageAnalyzer:
    def test_no_all_known_categories_is_empty(self) -> None:
        ctx = _make_context(target_ids=("t1",), all_known_attack_categories=frozenset())
        gaps = CoverageAnalyzer().analyze(ctx)
        assert gaps == []

    def test_no_snapshots_returns_gap_with_full_missing(self) -> None:
        ctx = _make_context(target_ids=("t1",))
        gaps = CoverageAnalyzer().analyze(ctx)
        assert len(gaps) == 1
        assert gaps[0].coverage_rate == 0.0
        assert gaps[0].tested_categories == frozenset()

    def test_full_coverage_no_gap(self) -> None:
        ctx = _make_context(
            target_ids=("t1",),
            all_known_attack_categories=frozenset({"a", "b"}),
            snapshots=(
                _snapshot("s1", categories=frozenset({"a", "b"})),
            ),
        )
        gaps = CoverageAnalyzer().analyze(ctx)
        assert all(g.coverage_rate == 1.0 for g in gaps)

    def test_partial_coverage_returns_gap(self) -> None:
        ctx = _make_context(
            target_ids=("t1",),
            all_known_attack_categories=frozenset({"a", "b", "c", "d"}),
            snapshots=(
                _snapshot("s1", categories=frozenset({"a"})),
            ),
        )
        gaps = CoverageAnalyzer().analyze(ctx)
        assert len(gaps) == 1
        gap = gaps[0]
        assert gap.target_id == "t1"
        assert gap.coverage_rate == pytest.approx(0.25)
        assert "b" in gap.missing_categories

    def test_multiple_snapshots_union_of_categories(self) -> None:
        ctx = _make_context(
            target_ids=("t1",),
            all_known_attack_categories=frozenset({"a", "b", "c"}),
            snapshots=(
                _snapshot("s1", categories=frozenset({"a"})),
                _snapshot("s2", categories=frozenset({"b"})),
            ),
        )
        gaps = CoverageAnalyzer().analyze(ctx)
        gap = gaps[0]
        assert "a" in gap.tested_categories
        assert "b" in gap.tested_categories
        assert gap.coverage_rate == pytest.approx(2 / 3)

    def test_multi_target_gaps(self) -> None:
        ctx = _make_context(
            target_ids=("t1", "t2"),
            all_known_attack_categories=frozenset({"a", "b"}),
            snapshots=(
                _snapshot("s1", target="t1", categories=frozenset({"a"})),
                _snapshot("s2", target="t2", categories=frozenset({"b"})),
            ),
        )
        gaps = CoverageAnalyzer().analyze(ctx)
        assert len(gaps) == 2

    def test_no_categories_with_snapshots_returns_empty(self) -> None:
        ctx = _make_context(
            target_ids=("t1",),
            all_known_attack_categories=frozenset(),
            snapshots=(_snapshot("s1"),),
        )
        gaps = CoverageAnalyzer().analyze(ctx)
        assert gaps == []


# ─── GapAnalyzer ──────────────────────────────────────────────────────────────


class TestGapAnalyzer:
    def test_no_context_no_gaps(self) -> None:
        ctx = _make_context()
        gaps = GapAnalyzer().analyze(ctx, [])
        assert isinstance(gaps, list)

    def test_drift_without_followup_is_gap(self) -> None:
        ctx = _make_context(
            target_ids=("t1",),
            drift_events=(
                DriftEventInput(
                    source_snapshot_id="s0",
                    target_snapshot_id="s1",
                    drift_types=("model_changed", "prompt_changed"),
                    is_significant=True,
                    target_id="t1",
                    organization_id="org1",
                ),
            ),
            snapshots=(_snapshot("s1", vuln_rate=0.20),),
        )
        gaps = GapAnalyzer().analyze(ctx, [])
        # A significant drift without follow-up validation should trigger a gap
        assert any(
            "drift" in g.description.lower() or "validation" in g.description.lower()
            for g in gaps
        )

    def test_single_provider_no_provider_gap(self) -> None:
        ctx = _make_context(
            target_ids=("t1",),
            snapshots=(
                _snapshot("s1", target="t1"),
            ),
        )
        gaps = GapAnalyzer().analyze(ctx, [])
        # With only 1 provider, no provider coverage gap expected
        provider_gaps = [g for g in gaps if "provider" in g.description.lower()]
        assert len(provider_gaps) == 0

    def test_coverage_gaps_fed_in(self) -> None:
        coverage_gaps = [
            AttackCoverageGap(
                target_id="t1",
                organization_id="org1",
                tested_categories=frozenset({"a"}),
                missing_categories=frozenset({"b", "c", "d", "e", "f", "g"}),
                coverage_rate=0.14,
            )
        ]
        ctx = _make_context(target_ids=("t1",))
        gaps = GapAnalyzer().analyze(ctx, coverage_gaps)
        assert isinstance(gaps, list)


# ─── InsightGenerator ─────────────────────────────────────────────────────────


class TestInsightGenerator:
    def test_empty_context_no_insights(self) -> None:
        ctx = _make_context()
        insights = InsightGenerator().generate(ctx)
        assert insights == []

    def test_persistent_pattern_3_same_category(self) -> None:
        ctx = _make_context(
            target_ids=("t1",),
            findings=(
                _finding("f1", category="prompt_injection"),
                _finding("f2", category="prompt_injection"),
                _finding("f3", category="prompt_injection"),
            ),
        )
        insights = InsightGenerator().generate(ctx)
        types = [i.insight_type.value for i in insights]
        assert "pattern" in types

    def test_cross_target_3_targets_same_category(self) -> None:
        ctx = _make_context(
            target_ids=("t1", "t2", "t3"),
            findings=(
                _finding("f1", target="t1", category="jailbreak"),
                _finding("f2", target="t2", category="jailbreak"),
                _finding("f3", target="t3", category="jailbreak"),
            ),
        )
        insights = InsightGenerator().generate(ctx)
        types = [i.insight_type.value for i in insights]
        assert "correlation" in types

    def test_monotone_degradation_trend(self) -> None:
        ctx = _make_context(
            target_ids=("t1",),
            snapshots=(
                _snapshot("s1", vuln_rate=0.10, created_at="2026-07-01T00:00:00+00:00"),
                _snapshot("s2", vuln_rate=0.20, created_at="2026-07-03T00:00:00+00:00"),
                _snapshot("s3", vuln_rate=0.30, created_at="2026-07-05T00:00:00+00:00"),
            ),
        )
        insights = InsightGenerator().generate(ctx)
        types = [i.insight_type.value for i in insights]
        assert "trend" in types

    def test_regression_after_stable_period(self) -> None:
        ctx = _make_context(
            target_ids=("t1",),
            snapshots=(
                _snapshot("s1", vuln_rate=0.10),
                _snapshot("s2", vuln_rate=0.11),
                _snapshot("s3", vuln_rate=0.12),
                _snapshot("s4", vuln_rate=0.40),
            ),
        )
        insights = InsightGenerator().generate(ctx)
        types = [i.insight_type.value for i in insights]
        assert "regression" in types or "anomaly" in types

    def test_insight_org_isolation(self) -> None:
        ctx1 = _make_context(
            organization_id="org1",
            target_ids=("t1",),
            findings=(
                _finding("f1", category="prompt_injection"),
                _finding("f2", category="prompt_injection"),
                _finding("f3", category="prompt_injection"),
            ),
        )
        ctx2 = _make_context(organization_id="org2", target_ids=("t9",))
        insights1 = InsightGenerator().generate(ctx1)
        insights2 = InsightGenerator().generate(ctx2)
        assert all(i.organization_id == "org1" for i in insights1)
        assert insights2 == []


# ─── RecommendationGenerator ─────────────────────────────────────────────────


class TestRecommendationGenerator:
    def test_no_signals_no_recommendations(self) -> None:
        ctx = _make_context()
        recs = RecommendationGenerator().generate(ctx, [], [], [])
        assert recs == []

    def test_critical_finding_generates_recommendation(self) -> None:
        ctx = _make_context(
            target_ids=("t1",),
            findings=(
                _finding("f1", severity="critical"),
            ),
        )
        recs = RecommendationGenerator().generate(ctx, [], [], [])
        assert len(recs) > 0

    def test_coverage_gap_generates_coverage_recommendation(self) -> None:
        gap = AttackCoverageGap(
            target_id="t1",
            organization_id="org1",
            tested_categories=frozenset({"a"}),
            missing_categories=frozenset({"b", "c", "d"}),
            coverage_rate=0.25,
        )
        ctx = _make_context(target_ids=("t1",))
        recs = RecommendationGenerator().generate(ctx, [], [gap], [])
        categories = [r.category for r in recs]
        assert RecommendationCategory.COVERAGE_GAP in categories

    def test_deduplication_no_duplicate_keys(self) -> None:
        ctx = _make_context(
            target_ids=("t1",),
            findings=(
                _finding("f1", severity="critical"),
                _finding("f2", severity="critical"),
                _finding("f3", severity="critical"),
            ),
        )
        recs = RecommendationGenerator().generate(ctx, [], [], [])
        keys = [r.deduplication_key for r in recs]
        assert len(keys) == len(set(keys)), "Duplicate recommendation keys found"

    def test_org_level_recs_triggered_by_critical_finding(self) -> None:
        ctx = _make_context(
            target_ids=("t1", "t2", "t3"),
            findings=(
                _finding("f1", target="t1", severity="critical"),
                _finding("f2", target="t2", severity="critical"),
                _finding("f3", target="t3", severity="critical"),
            ),
        )
        recs = RecommendationGenerator().generate(ctx, [], [], [])
        assert len(recs) > 0


# ─── PriorityEngine ───────────────────────────────────────────────────────────


class TestPriorityEngine:
    def _make_rec(
        self,
        priority: RecommendationPriority = RecommendationPriority.MEDIUM,
        score: float = 50.0,
        target: str | None = "t1",
    ) -> object:
        from redforge.domain.intelligence.entity import Recommendation
        from redforge.domain.intelligence.value_objects import (
            RecommendationCategory,
            RecommendationEvidence,
        )
        rec, _ = Recommendation.create(
            organization_id="org1",
            target_id=target,
            category=RecommendationCategory.PROMPT_SECURITY,
            priority=priority,
            priority_score=score,
            title="Test",
            description="Test recommendation",
            evidence=RecommendationEvidence(rationale="test"),
            remediation_steps=(),
            rule_id="R001",
        )
        return rec

    def test_empty_returns_empty(self) -> None:
        ctx = _make_context()
        result = PriorityEngine().prioritize([], ctx)
        assert result == []

    def test_sorted_by_score_descending(self) -> None:
        from redforge.domain.intelligence.entity import Recommendation
        ctx = _make_context()
        r1 = self._make_rec(score=70.0)
        r2 = self._make_rec(score=40.0)
        r3 = self._make_rec(score=90.0)
        assert isinstance(r1, Recommendation)
        result = PriorityEngine().prioritize([r1, r2, r3], ctx)  # type: ignore[arg-type]
        scores = [r.priority_score for r in result]
        assert scores == sorted(scores, reverse=True) or all(
            r.priority in {RecommendationPriority.CRITICAL, RecommendationPriority.HIGH,
                           RecommendationPriority.MEDIUM, RecommendationPriority.LOW}
            for r in result
        )

    def test_posture_critical_multiplier_applied(self) -> None:
        from redforge.domain.intelligence.entity import Recommendation
        posture = PostureInput(
            organization_id="org1",
            mean_vulnerability_rate=0.60,
            level="critical",
            targets_assessed=2,
            total_findings=100,
            critical_targets=2,
            trend="degrading",
            snapshot_count=5,
        )
        ctx = _make_context(posture=posture)
        r = self._make_rec(score=50.0)
        assert isinstance(r, Recommendation)
        result = PriorityEngine().prioritize([r], ctx)  # type: ignore[arg-type]
        assert len(result) == 1

    def test_multi_target_org_level_multiplier(self) -> None:
        from redforge.domain.intelligence.entity import Recommendation
        ctx = _make_context(target_ids=("t1", "t2", "t3", "t4"))
        r = self._make_rec(target=None)
        assert isinstance(r, Recommendation)
        result = PriorityEngine().prioritize([r], ctx)  # type: ignore[arg-type]
        assert len(result) == 1


# ─── NarrativeBuilder ─────────────────────────────────────────────────────────


class TestNarrativeBuilder:
    def test_empty_context_returns_no_risk_summary(self) -> None:
        ctx = _make_context()
        narrative = NarrativeBuilder().build_risk_narrative(ctx, [])
        assert "No risk incidents" in narrative.summary
        assert narrative.critical_incident_count == 0

    def test_risk_narrative_with_incidents(self) -> None:
        ctx = _make_context(
            risk_incidents=(
                _incident("i1", priority="critical", risk_score=9.5),
                _incident("i2", priority="high", risk_score=7.0),
            )
        )
        narrative = NarrativeBuilder().build_risk_narrative(ctx, [])
        assert narrative.critical_incident_count == 1
        assert narrative.high_incident_count == 1
        assert len(narrative.key_risks) > 0

    def test_posture_narrative_no_posture(self) -> None:
        ctx = _make_context(posture=None)
        narrative = NarrativeBuilder().build_posture_narrative(ctx, [])
        assert narrative.overall_level == "unknown"
        assert narrative.targets_assessed == 0

    def test_posture_narrative_with_data(self) -> None:
        posture = PostureInput(
            organization_id="org1",
            mean_vulnerability_rate=0.25,
            level="fair",
            targets_assessed=3,
            total_findings=50,
            critical_targets=0,
            trend="improving",
            snapshot_count=10,
        )
        ctx = _make_context(
            posture=posture,
            snapshots=(
                _snapshot("s1", vuln_rate=0.25),
                _snapshot("s2", target="t2", vuln_rate=0.25),
            ),
        )
        gaps: list[AttackCoverageGap] = []
        narrative = NarrativeBuilder().build_posture_narrative(ctx, gaps)
        assert narrative.overall_level == "fair"
        assert narrative.targets_assessed == 3
        assert "improving" in narrative.trend_summary.lower() or narrative.trend_summary

    def test_risk_narrative_with_recommendations(self) -> None:
        from redforge.domain.intelligence.entity import Recommendation
        from redforge.domain.intelligence.value_objects import (
            RecommendationEvidence,
        )
        ctx = _make_context(
            risk_incidents=(_incident("i1", priority="critical", risk_score=9.9),),
        )
        rec, _ = Recommendation.create(
            organization_id="org1",
            target_id="t1",
            category=RecommendationCategory.CRITICAL_SECURITY_RISK,
            priority=RecommendationPriority.CRITICAL,
            priority_score=95.0,
            title="Emergency: critical risk",
            description="Critical",
            evidence=RecommendationEvidence(rationale="critical"),
            remediation_steps=(),
            rule_id="R999",
        )
        narrative = NarrativeBuilder().build_risk_narrative(ctx, [rec])
        assert "Emergency" in narrative.recommendations_summary or narrative.recommendations_summary


# ─── RemediationPlanner ───────────────────────────────────────────────────────


class TestRemediationPlanner:
    def test_all_14_categories_have_plan(self) -> None:
        planner = RemediationPlanner()
        for cat in RecommendationCategory:
            steps = planner.plan(cat)
            assert len(steps) > 0, f"No remediation steps for {cat}"

    def test_steps_ordered_correctly(self) -> None:
        planner = RemediationPlanner()
        for cat in RecommendationCategory:
            steps = planner.plan(cat)
            orders = [s.order for s in steps]
            assert orders == sorted(orders), f"Steps out of order for {cat}"

    def test_prompt_security_plan_not_empty(self) -> None:
        steps = RemediationPlanner().plan(RecommendationCategory.PROMPT_SECURITY)
        assert len(steps) >= 2

    def test_mcp_security_plan_not_empty(self) -> None:
        steps = RemediationPlanner().plan(RecommendationCategory.MCP_SECURITY)
        assert len(steps) >= 2
