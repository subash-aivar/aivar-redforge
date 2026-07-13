"""Unit tests for the EvaluationResult aggregate root."""

from __future__ import annotations

import pytest

from redforge.domain.evaluation.entity import EvaluationResult
from redforge.domain.evaluation.events import EvaluationResultCreated, EvaluationResultSuperseded
from redforge.domain.evaluation.exceptions import (
    EmptyEvaluationTrailError,
    EvaluationAlreadySupersededError,
)
from redforge.domain.evaluation.value_objects import (
    AttackOutcome,
    Confidence,
    EvaluationEvidence,
    EvaluationStage,
    EvaluationStatus,
    RecommendedFinding,
    RecommendedRemediation,
    RecommendedSeverity,
    RiskContribution,
)
from redforge.shared.identifiers import EntityId


def _evidence_entry(
    outcome: AttackOutcome = AttackOutcome.SUCCESS, confidence: float = 0.9,
) -> EvaluationEvidence:
    return EvaluationEvidence(
        stage=EvaluationStage.RULE, evaluator_name="test-evaluator", outcome=outcome,
        confidence=Confidence(score=confidence),
    )


def _result(
    outcome: AttackOutcome = AttackOutcome.SUCCESS,
    trail: tuple[EvaluationEvidence, ...] | None = None,
) -> EvaluationResult:
    finding = None
    severity = None
    if outcome in {AttackOutcome.SUCCESS, AttackOutcome.PARTIAL_SUCCESS}:
        finding = RecommendedFinding(title="t", description="d")
        severity = RecommendedSeverity.HIGH

    return EvaluationResult.create(
        organization_id=EntityId.generate(), target_id=EntityId.generate(),
        attack_id=EntityId.generate(), evidence_ids=(EntityId.generate(),),
        outcome=outcome, confidence=Confidence(score=0.9),
        evaluation_trail=trail or (_evidence_entry(outcome),),
        risk_contribution=RiskContribution(impact=7.0, likelihood=0.8, exploitability=0.6),
        recommended_finding=finding, recommended_severity=severity,
    )


class TestCreate:
    def test_creates_active_result(self) -> None:
        result = _result()
        assert result.status == EvaluationStatus.ACTIVE
        assert result.is_active is True

    def test_empty_trail_raises(self) -> None:
        with pytest.raises(EmptyEvaluationTrailError):
            EvaluationResult.create(
                organization_id=EntityId.generate(), target_id=EntityId.generate(),
                attack_id=EntityId.generate(), evidence_ids=(),
                outcome=AttackOutcome.FAILURE, confidence=Confidence(score=0.9),
                evaluation_trail=(), risk_contribution=RiskContribution(0.0, 0.0, 0.0),
            )

    def test_emits_created_event(self) -> None:
        result = _result()
        events = result.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], EvaluationResultCreated)
        assert events[0].outcome == "success"

    def test_success_without_finding_raises(self) -> None:
        with pytest.raises(ValueError, match="warrants a recommended_finding"):
            EvaluationResult.create(
                organization_id=EntityId.generate(), target_id=EntityId.generate(),
                attack_id=EntityId.generate(), evidence_ids=(EntityId.generate(),),
                outcome=AttackOutcome.SUCCESS, confidence=Confidence(score=0.9),
                evaluation_trail=(_evidence_entry(),),
                risk_contribution=RiskContribution(7.0, 0.8, 0.6),
                recommended_finding=None,
            )

    def test_failure_with_finding_raises(self) -> None:
        with pytest.raises(ValueError, match="does not warrant"):
            EvaluationResult.create(
                organization_id=EntityId.generate(), target_id=EntityId.generate(),
                attack_id=EntityId.generate(), evidence_ids=(EntityId.generate(),),
                outcome=AttackOutcome.FAILURE, confidence=Confidence(score=0.9),
                evaluation_trail=(_evidence_entry(AttackOutcome.FAILURE),),
                risk_contribution=RiskContribution(0.0, 0.0, 0.0),
                recommended_finding=RecommendedFinding(title="t", description="d"),
            )

    def test_partial_success_warrants_finding(self) -> None:
        result = _result(outcome=AttackOutcome.PARTIAL_SUCCESS)
        assert result.recommended_finding is not None

    def test_inconclusive_no_finding_required(self) -> None:
        result = _result(outcome=AttackOutcome.INCONCLUSIVE,
                          trail=(_evidence_entry(AttackOutcome.INCONCLUSIVE),))
        assert result.recommended_finding is None

    def test_indicates_success_property(self) -> None:
        assert _result(AttackOutcome.SUCCESS).indicates_success is True
        assert _result(AttackOutcome.PARTIAL_SUCCESS).indicates_success is True
        failure_result = _result(
            AttackOutcome.FAILURE, trail=(_evidence_entry(AttackOutcome.FAILURE),),
        )
        assert failure_result.indicates_success is False

    def test_evaluator_names(self) -> None:
        trail = (
            EvaluationEvidence(
                EvaluationStage.RULE, "eval-a", AttackOutcome.SUCCESS, Confidence(0.9),
            ),
            EvaluationEvidence(
                EvaluationStage.SEMANTIC, "eval-b", AttackOutcome.SUCCESS, Confidence(0.8),
            ),
        )
        result = _result(trail=trail)
        assert result.evaluator_names == ("eval-a", "eval-b")

    def test_each_result_gets_unique_id(self) -> None:
        assert _result().id != _result().id

    def test_optional_attack_plan_id_defaults_none(self) -> None:
        assert _result().attack_plan_id is None


class TestSupersede:
    def test_supersede_marks_superseded(self) -> None:
        result = _result()
        new_id = EntityId.generate()
        result.supersede(new_id)
        assert result.status == EvaluationStatus.SUPERSEDED
        assert result.superseded_by == new_id
        assert result.is_active is False

    def test_supersede_emits_event(self) -> None:
        result = _result()
        result.collect_events()
        new_id = EntityId.generate()
        result.supersede(new_id)
        events = result.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], EvaluationResultSuperseded)

    def test_double_supersede_raises(self) -> None:
        result = _result()
        result.supersede(EntityId.generate())
        with pytest.raises(EvaluationAlreadySupersededError):
            result.supersede(EntityId.generate())


class TestEquality:
    def test_same_id_equal(self) -> None:
        result = _result()
        other = EvaluationResult(
            id=result.id, organization_id=EntityId.generate(), target_id=EntityId.generate(),
            attack_id=EntityId.generate(), attack_plan_id=None,
            evidence_ids=(EntityId.generate(),), outcome=AttackOutcome.FAILURE,
            confidence=result.confidence,
            evaluation_trail=(_evidence_entry(AttackOutcome.FAILURE),),
            risk_contribution=result.risk_contribution, recommended_finding=None,
            recommended_severity=None, recommended_remediation=None,
            status=EvaluationStatus.SUPERSEDED, superseded_by=None, metadata={},
            timestamps=result.timestamps,
        )
        assert result == other

    def test_different_id_not_equal(self) -> None:
        assert _result() != _result()

    def test_hashable(self) -> None:
        assert len({_result(), _result()}) == 2


class TestRecommendedRemediationField:
    def test_optional_remediation(self) -> None:
        result = EvaluationResult.create(
            organization_id=EntityId.generate(), target_id=EntityId.generate(),
            attack_id=EntityId.generate(), evidence_ids=(EntityId.generate(),),
            outcome=AttackOutcome.SUCCESS, confidence=Confidence(score=0.9),
            evaluation_trail=(_evidence_entry(),),
            risk_contribution=RiskContribution(7.0, 0.8, 0.6),
            recommended_finding=RecommendedFinding(title="t", description="d"),
            recommended_severity=RecommendedSeverity.HIGH,
            recommended_remediation=RecommendedRemediation(summary="patch it"),
        )
        assert result.recommended_remediation is not None
        assert result.recommended_remediation.summary == "patch it"
