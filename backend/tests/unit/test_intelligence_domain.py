"""Unit tests for the AI Security Intelligence domain layer.

Tests value objects, entity lifecycle, domain events, and exceptions.
"""

from __future__ import annotations

import pytest

from redforge.domain.intelligence.entity import (
    IntelligenceReport,
    Recommendation,
    SecurityInsight,
)
from redforge.domain.intelligence.events import (
    CoverageGapIdentified,
    InsightDetected,
    IntelligenceReportCreated,
    RecommendationGenerated,
)
from redforge.domain.intelligence.exceptions import (
    DuplicateRecommendationError,
    IntelligenceDomainError,
    RecommendationAlreadyTerminalError,
    RecommendationNotFoundError,
)
from redforge.domain.intelligence.value_objects import (
    AttackCoverageGap,
    InsightType,
    PostureNarrative,
    RecommendationCategory,
    RecommendationEvidence,
    RecommendationPriority,
    RecommendationRule,
    RecommendationStatus,
    RemediationEffort,
    RemediationStep,
    RiskNarrative,
    SecurityTrend,
)

# ─── Value Object Tests ────────────────────────────────────────────────────────


class TestRecommendationPriority:
    def test_values(self) -> None:
        assert RecommendationPriority.CRITICAL == "critical"
        assert RecommendationPriority.HIGH == "high"
        assert RecommendationPriority.MEDIUM == "medium"
        assert RecommendationPriority.LOW == "low"

    def test_all_four_exist(self) -> None:
        assert len(RecommendationPriority) == 4


class TestRecommendationCategory:
    def test_all_fourteen_categories(self) -> None:
        assert len(RecommendationCategory) == 14

    def test_key_categories(self) -> None:
        assert RecommendationCategory.CRITICAL_SECURITY_RISK == "critical_security_risk"
        assert RecommendationCategory.MCP_SECURITY == "mcp_security"
        assert RecommendationCategory.COVERAGE_GAP == "coverage_gap"
        assert RecommendationCategory.COMPLIANCE_GAP == "compliance_gap"


class TestInsightType:
    def test_all_six_types(self) -> None:
        assert len(InsightType) == 6

    def test_values(self) -> None:
        assert InsightType.PATTERN == "pattern"
        assert InsightType.ANOMALY == "anomaly"
        assert InsightType.REGRESSION == "regression"


class TestRecommendationEvidence:
    def test_defaults_empty(self) -> None:
        ev = RecommendationEvidence(rationale="test")
        assert ev.finding_ids == ()
        assert ev.risk_incident_ids == ()
        assert ev.total_references == 0

    def test_total_references_sum(self) -> None:
        ev = RecommendationEvidence(
            rationale="r",
            finding_ids=("f1", "f2"),
            risk_incident_ids=("i1",),
            evidence_chain_ids=("e1", "e2", "e3"),
        )
        assert ev.total_references == 6

    def test_is_well_supported_false_below_3(self) -> None:
        ev = RecommendationEvidence(rationale="r", finding_ids=("f1", "f2"))
        assert not ev.is_well_supported

    def test_is_well_supported_true_two_sources(self) -> None:
        ev = RecommendationEvidence(
            rationale="r",
            finding_ids=("f1", "f2", "f3"),
            risk_incident_ids=("i1",),
        )
        assert ev.is_well_supported


class TestAttackCoverageGap:
    def test_coverage_rate_100(self) -> None:
        gap = AttackCoverageGap(
            target_id="t1",
            organization_id="org1",
            tested_categories=frozenset({"a", "b"}),
            missing_categories=frozenset(),
            coverage_rate=1.0,
        )
        assert gap.gap_severity == RecommendationPriority.LOW

    def test_gap_severity_critical_below_25(self) -> None:
        gap = AttackCoverageGap(
            target_id="t1",
            organization_id="org1",
            tested_categories=frozenset({"a"}),
            missing_categories=frozenset({"b", "c", "d", "e", "f"}),
            coverage_rate=0.20,
        )
        assert gap.gap_severity == RecommendationPriority.CRITICAL

    def test_gap_severity_high_25_to_50(self) -> None:
        gap = AttackCoverageGap(
            target_id="t1",
            organization_id="org1",
            tested_categories=frozenset({"a", "b"}),
            missing_categories=frozenset({"c", "d", "e"}),
            coverage_rate=0.40,
        )
        assert gap.gap_severity == RecommendationPriority.HIGH

    def test_gap_severity_medium_50_to_75(self) -> None:
        gap = AttackCoverageGap(
            target_id="t1",
            organization_id="org1",
            tested_categories=frozenset({"a", "b", "c"}),
            missing_categories=frozenset({"d", "e"}),
            coverage_rate=0.60,
        )
        assert gap.gap_severity == RecommendationPriority.MEDIUM


class TestRemediationStep:
    def test_frozen(self) -> None:
        step = RemediationStep(
            order=1,
            title="Test",
            description="Do the thing",
            effort=RemediationEffort.IMMEDIATE,
        )
        with pytest.raises(AttributeError):
            step.order = 2  # type: ignore[misc]

    def test_defaults(self) -> None:
        step = RemediationStep(
            order=1, title="T", description="D", effort=RemediationEffort.SHORT_TERM
        )
        assert not step.automation_available
        assert step.reference_url == ""


class TestSecurityTrend:
    def test_frozen(self) -> None:
        trend = SecurityTrend(
            metric="vulnerability_rate",
            direction="improving",
            period_days=30,
            delta=-0.05,
            snapshot_count=5,
            description="Getting better",
        )
        assert trend.delta == -0.05


class TestRiskNarrative:
    def test_frozen(self) -> None:
        n = RiskNarrative(
            summary="s",
            key_risks=("r1", "r2"),
            trend_description="t",
            recommendations_summary="rs",
            critical_incident_count=1,
            high_incident_count=2,
        )
        assert n.critical_incident_count == 1


class TestPostureNarrative:
    def test_frozen(self) -> None:
        n = PostureNarrative(
            overall_level="good",
            trend_summary="improving",
            targets_assessed=3,
            critical_targets=(),
            improvement_areas=("area1",),
            mean_vulnerability_rate=0.10,
        )
        assert n.targets_assessed == 3


class TestRecommendationRule:
    def test_frozen(self) -> None:
        rule = RecommendationRule(
            rule_id="R001",
            name="Test Rule",
            category=RecommendationCategory.PROMPT_SECURITY,
            default_priority=RecommendationPriority.HIGH,
            condition_description="when prompt injection detected",
            version="1.0",
        )
        with pytest.raises(AttributeError):
            rule.rule_id = "changed"  # type: ignore[misc]


# ─── SecurityInsight Entity Tests ─────────────────────────────────────────────


class TestSecurityInsight:
    def _make_insight(self, **kwargs: object) -> tuple[SecurityInsight, list]:
        defaults = dict(
            organization_id="org1",
            insight_type=InsightType.PATTERN,
            title="Persistent Prompt Injection",
            description="Same attack category fails repeatedly",
            affected_targets=("t1", "t2"),
            supporting_finding_ids=("f1", "f2"),
            supporting_incident_ids=("i1",),
            confidence=0.85,
        )
        defaults.update(kwargs)  # type: ignore[arg-type]
        return SecurityInsight.create(**defaults)  # type: ignore[arg-type]

    def test_create_returns_insight_and_events(self) -> None:
        insight, events = self._make_insight()
        assert insight.organization_id == "org1"
        assert len(events) == 1
        assert isinstance(events[0], InsightDetected)

    def test_event_fields(self) -> None:
        _insight, events = self._make_insight()
        ev = events[0]
        assert ev.organization_id == "org1"
        assert ev.insight_type == InsightType.PATTERN
        assert ev.affected_target_count == 2

    def test_is_high_confidence_above_threshold(self) -> None:
        insight, _ = self._make_insight(confidence=0.80)
        assert insight.is_high_confidence

    def test_is_not_high_confidence_below_threshold(self) -> None:
        insight, _ = self._make_insight(confidence=0.60)
        assert not insight.is_high_confidence

    def test_immutable_slots(self) -> None:
        insight, _ = self._make_insight()
        with pytest.raises(AttributeError):
            insight.not_real = "x"  # type: ignore[attr-defined]

    def test_id_is_string(self) -> None:
        insight, _ = self._make_insight()
        assert isinstance(insight.id, str)
        assert len(insight.id) > 0


# ─── Recommendation Entity Tests ──────────────────────────────────────────────


class TestRecommendation:
    def _make_rec(self, **kwargs: object) -> tuple[Recommendation, list]:
        defaults = dict(
            organization_id="org1",
            target_id="t1",
            category=RecommendationCategory.PROMPT_SECURITY,
            priority=RecommendationPriority.HIGH,
            priority_score=70.0,
            title="Enable Prompt Injection Detection",
            description="Deploy guardrails against prompt injection attacks.",
            evidence=RecommendationEvidence(
                rationale="3 critical findings", finding_ids=("f1", "f2", "f3")
            ),
            remediation_steps=(
                RemediationStep(
                    order=1,
                    title="Deploy input validation",
                    description="Validate user inputs",
                    effort=RemediationEffort.IMMEDIATE,
                ),
            ),
            rule_id="R001",
        )
        defaults.update(kwargs)  # type: ignore[arg-type]
        return Recommendation.create(**defaults)  # type: ignore[arg-type]

    def test_create_returns_rec_and_event(self) -> None:
        rec, events = self._make_rec()
        assert rec.organization_id == "org1"
        assert len(events) == 1
        assert isinstance(events[0], RecommendationGenerated)

    def test_initial_status_active(self) -> None:
        rec, _ = self._make_rec()
        assert rec.status == RecommendationStatus.ACTIVE

    def test_acknowledge_transition(self) -> None:
        rec, _ = self._make_rec()
        rec.acknowledge()
        assert rec.status == RecommendationStatus.ACKNOWLEDGED

    def test_mark_implemented(self) -> None:
        rec, _ = self._make_rec()
        rec.acknowledge()
        rec.mark_implemented()
        assert rec.status == RecommendationStatus.IMPLEMENTED

    def test_dismiss_transition(self) -> None:
        rec, _ = self._make_rec()
        rec.dismiss()
        assert rec.status == RecommendationStatus.DISMISSED

    def test_terminal_guard_on_implemented(self) -> None:
        rec, _ = self._make_rec()
        rec.mark_implemented()
        with pytest.raises(RecommendationAlreadyTerminalError):
            rec.dismiss()

    def test_terminal_guard_on_dismissed(self) -> None:
        rec, _ = self._make_rec()
        rec.dismiss()
        with pytest.raises(RecommendationAlreadyTerminalError):
            rec.acknowledge()

    def test_deduplication_key_format(self) -> None:
        rec, _ = self._make_rec()
        key = rec.deduplication_key
        assert "org1" in key
        assert "t1" in key
        assert "prompt_security" in key
        assert "R001" in key

    def test_org_level_rec_no_target(self) -> None:
        rec, _ = self._make_rec(target_id=None)
        assert rec.target_id is None
        assert "None" in rec.deduplication_key or ":" in rec.deduplication_key


# ─── IntelligenceReport Entity Tests ──────────────────────────────────────────


class TestIntelligenceReport:
    def _make_report(self) -> tuple[IntelligenceReport, list]:
        insight, _ = SecurityInsight.create(
            organization_id="org1",
            insight_type=InsightType.PATTERN,
            title="Pattern",
            description="Desc",
            affected_targets=("t1",),
            supporting_finding_ids=("f1",),
            supporting_incident_ids=(),
            confidence=0.9,
        )
        rec, _ = Recommendation.create(
            organization_id="org1",
            target_id="t1",
            category=RecommendationCategory.PROMPT_SECURITY,
            priority=RecommendationPriority.CRITICAL,
            priority_score=90.0,
            title="Critical Fix",
            description="Fix this now",
            evidence=RecommendationEvidence(rationale="critical"),
            remediation_steps=(),
            rule_id="R001",
        )
        gap = AttackCoverageGap(
            target_id="t1",
            organization_id="org1",
            tested_categories=frozenset({"a"}),
            missing_categories=frozenset({"b", "c"}),
            coverage_rate=0.33,
        )
        risk_narrative = RiskNarrative(
            summary="summary",
            key_risks=(),
            trend_description="stable",
            recommendations_summary="fix it",
            critical_incident_count=1,
            high_incident_count=0,
        )
        posture_narrative = PostureNarrative(
            overall_level="poor",
            trend_summary="degrading",
            targets_assessed=1,
            critical_targets=(),
            improvement_areas=(),
            mean_vulnerability_rate=0.55,
        )
        return IntelligenceReport.assemble(
            organization_id="org1",
            target_ids=("t1",),
            insights=(insight,),
            recommendations=(rec,),
            coverage_gaps=(gap,),
            security_gaps=(),
            risk_narrative=risk_narrative,
            posture_narrative=posture_narrative,
            period_days=30,
        )

    def test_assemble_returns_report_and_event(self) -> None:
        report, events = self._make_report()
        assert report.organization_id == "org1"
        assert len(events) == 1
        assert isinstance(events[0], IntelligenceReportCreated)

    def test_critical_recommendation_count(self) -> None:
        report, _ = self._make_report()
        assert report.critical_recommendation_count == 1
        assert report.has_critical_recommendations

    def test_report_aggregates_all(self) -> None:
        report, _ = self._make_report()
        assert len(report.recommendations) == 1
        assert len(report.insights) == 1
        assert len(report.coverage_gaps) == 1

    def test_id_is_string(self) -> None:
        report, _ = self._make_report()
        assert isinstance(report.id, str)


# ─── Exception Tests ───────────────────────────────────────────────────────────


class TestIntelligenceExceptions:
    def test_base_error_hierarchy(self) -> None:
        e = IntelligenceDomainError("test")
        assert isinstance(e, Exception)

    def test_not_found_inherits_base(self) -> None:
        e = RecommendationNotFoundError("rec-123")
        assert isinstance(e, IntelligenceDomainError)

    def test_already_terminal_inherits_base(self) -> None:
        e = RecommendationAlreadyTerminalError("rec-123", "dismissed")
        assert isinstance(e, IntelligenceDomainError)

    def test_duplicate_recommendation_inherits_base(self) -> None:
        e = DuplicateRecommendationError("org1:t1:prompt_security:R001")
        assert isinstance(e, IntelligenceDomainError)


# ─── Domain Event Tests ────────────────────────────────────────────────────────


class TestIntelligenceDomainEvents:
    def test_insight_detected_event(self) -> None:
        ev = InsightDetected(
            event_id="evt-1",
            insight_id="ins-1",
            organization_id="org1",
            insight_type=InsightType.PATTERN,
            title="Pattern detected",
            affected_target_count=3,
        )
        assert ev.organization_id == "org1"
        assert ev.affected_target_count == 3

    def test_recommendation_generated_event(self) -> None:
        ev = RecommendationGenerated(
            event_id="evt-2",
            recommendation_id="rec-1",
            organization_id="org1",
            target_id="t1",
            category=RecommendationCategory.MCP_SECURITY,
            priority=RecommendationPriority.HIGH,
            rule_id="R005",
        )
        assert ev.category == RecommendationCategory.MCP_SECURITY

    def test_coverage_gap_identified_event(self) -> None:
        ev = CoverageGapIdentified(
            event_id="evt-3",
            organization_id="org1",
            target_id="t1",
            missing_category_count=5,
            coverage_rate=0.30,
        )
        assert ev.missing_category_count == 5
        assert ev.coverage_rate == pytest.approx(0.30)

    def test_report_created_event(self) -> None:
        ev = IntelligenceReportCreated(
            event_id="evt-4",
            report_id="rpt-1",
            organization_id="org1",
            recommendation_count=10,
            insight_count=3,
            critical_recommendation_count=2,
        )
        assert ev.critical_recommendation_count == 2
