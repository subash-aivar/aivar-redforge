"""Unit tests for the Response Evaluation Intelligence value objects."""

from __future__ import annotations

import pytest

from redforge.domain.evaluation.value_objects import (
    AttackOutcome,
    Confidence,
    EvaluationEvidence,
    EvaluationStage,
    NormalizedEvidence,
    RecommendedFinding,
    RecommendedRemediation,
    RiskContribution,
)


class TestNormalizedEvidence:
    def test_defaults(self) -> None:
        n = NormalizedEvidence(
            request_text="req", response_text="resp", attack_category="prompt_injection",
            target_id="t1",
        )
        assert n.response_status == 0
        assert n.duration_ms == 0


class TestEvaluationEvidence:
    def test_empty_evaluator_name_raises(self) -> None:
        with pytest.raises(ValueError, match="evaluator_name"):
            EvaluationEvidence(
                stage=EvaluationStage.RULE, evaluator_name="", outcome=AttackOutcome.SUCCESS,
                confidence=Confidence(score=0.8),
            )

    def test_valid_construction(self) -> None:
        e = EvaluationEvidence(
            stage=EvaluationStage.RULE, evaluator_name="keyword", outcome=AttackOutcome.SUCCESS,
            confidence=Confidence(score=0.9), rationale="matched", indicators=("x",),
        )
        assert e.stage == EvaluationStage.RULE
        assert e.indicators == ("x",)


class TestRiskContribution:
    def test_valid_construction(self) -> None:
        r = RiskContribution(impact=7.5, likelihood=0.8, exploitability=0.6)
        assert r.impact == 7.5

    @pytest.mark.parametrize("impact", [-0.1, 10.1])
    def test_impact_out_of_range_raises(self, impact: float) -> None:
        with pytest.raises(ValueError, match="impact"):
            RiskContribution(impact=impact, likelihood=0.5, exploitability=0.5)

    @pytest.mark.parametrize("likelihood", [-0.1, 1.1])
    def test_likelihood_out_of_range_raises(self, likelihood: float) -> None:
        with pytest.raises(ValueError, match="likelihood"):
            RiskContribution(impact=5.0, likelihood=likelihood, exploitability=0.5)

    @pytest.mark.parametrize("exploitability", [-0.1, 1.1])
    def test_exploitability_out_of_range_raises(self, exploitability: float) -> None:
        with pytest.raises(ValueError, match="exploitability"):
            RiskContribution(impact=5.0, likelihood=0.5, exploitability=exploitability)

    def test_zero_contribution_is_valid(self) -> None:
        r = RiskContribution(impact=0.0, likelihood=0.0, exploitability=0.0)
        assert r.impact == 0.0


class TestRecommendedFinding:
    def test_empty_title_raises(self) -> None:
        with pytest.raises(ValueError, match="title"):
            RecommendedFinding(title="", description="d")

    def test_empty_description_raises(self) -> None:
        with pytest.raises(ValueError, match="description"):
            RecommendedFinding(title="t", description="")

    def test_valid_construction(self) -> None:
        f = RecommendedFinding(title="t", description="d", evidence_summary="s")
        assert f.evidence_summary == "s"


class TestRecommendedRemediation:
    def test_empty_summary_raises(self) -> None:
        with pytest.raises(ValueError, match="summary"):
            RecommendedRemediation(summary="")

    def test_invalid_priority_raises(self) -> None:
        with pytest.raises(ValueError, match="priority"):
            RecommendedRemediation(summary="fix it", priority="urgent")

    @pytest.mark.parametrize("priority", ["immediate", "high", "medium", "low"])
    def test_valid_priorities(self, priority: str) -> None:
        r = RecommendedRemediation(summary="fix it", priority=priority)
        assert r.priority == priority

    def test_default_priority_is_medium(self) -> None:
        assert RecommendedRemediation(summary="fix it").priority == "medium"
