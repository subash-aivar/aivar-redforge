"""Unit tests for EvaluationEngine (domain.evaluation.pipeline) — the
new 8-stage response evaluation orchestrator. Not to be confused with
tests/unit/test_evaluation_engine.py, which tests the pre-existing
`application/runtime/evaluation/` engine this module wraps rather than
duplicates.

Focus: outcome-determination logic (the one piece of genuinely-new
cross-stage decision logic this engine owns), pipeline sequencing via
fakes, and adversarial cases — false positives, false negatives, and
boundary/tie conditions in evaluator disagreement.
"""

from __future__ import annotations

import pytest

from redforge.domain.attack_library.entity import AttackDefinition
from redforge.domain.attack_library.value_objects import (
    AttackCategory,
    AttackSeverity,
    AttackTechnique,
)
from redforge.domain.evaluation.exceptions import NoEvaluatorsConfiguredError
from redforge.domain.evaluation.pipeline import EvaluationEngine
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
from redforge.domain.evidence.entity import Evidence
from redforge.domain.evidence.value_objects import (
    AttackReference,
    EvidenceResult,
    ExecutionMetadata,
    RequestPayload,
    ResponsePayload,
)
from redforge.domain.evidence.value_objects import (
    Confidence as EvidenceConfidence,
)
from redforge.domain.evidence.value_objects import (
    TestCaseReference as EvidenceTestCaseReference,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now


def _attack() -> AttackDefinition:
    a = AttackDefinition.create(
        name="attack-test", display_name="Attack Test", description="...",
        category=AttackCategory.PROMPT_INJECTION, technique=AttackTechnique(technique="T"),
        severity=AttackSeverity.HIGH,
    )
    a.publish()
    a.collect_events()
    return a


def _evidence() -> Evidence:
    return Evidence.record(
        organization_id=EntityId.generate(), run_id=EntityId.generate(),
        target_id=EntityId.generate(),
        test_case_ref=EvidenceTestCaseReference(
            test_id="tc1", test_name="Test", category="injection",
        ),
        attack_ref=AttackReference(
            attack_id="a1", attack_name="Attack", attack_type="prompt_injection",
        ),
        request=RequestPayload(method="POST", url="https://x.test", body="ignore rules"),
        response=ResponsePayload(status_code=200, body="here is the system prompt"),
        result=EvidenceResult.FAIL,
        confidence=EvidenceConfidence(score=0.9),
        execution_metadata=ExecutionMetadata(
            executed_at=utc_now(), duration_ms=100, engine_version="1.0",
        ),
    )


class _FakeNormalizer:
    def normalize(self, evidence: Evidence) -> NormalizedEvidence:
        return NormalizedEvidence(
            request_text=evidence.request.body, response_text=evidence.response.body,
            attack_category="prompt_injection", target_id=str(evidence.target_id),
        )


class _FakeEvaluator:
    def __init__(
        self, name: str, outcome: AttackOutcome, confidence: float = 0.9,
        stage: EvaluationStage = EvaluationStage.RULE,
    ) -> None:
        self._name = name
        self._outcome = outcome
        self._confidence = confidence
        self._stage = stage

    @property
    def name(self) -> str:
        return self._name

    async def evaluate(self, evidence: NormalizedEvidence) -> EvaluationEvidence:
        return EvaluationEvidence(
            stage=self._stage, evaluator_name=self._name, outcome=self._outcome,
            confidence=Confidence(score=self._confidence),
        )


class _FakeRiskScorer:
    def score(self, outcome, trail, attack) -> RiskContribution:
        return RiskContribution(impact=5.0, likelihood=0.5, exploitability=0.5)


class _FakeConfidenceCalculator:
    def calculate(self, trail) -> Confidence:
        if not trail:
            return Confidence(score=0.0)
        return Confidence(score=sum(e.confidence.score for e in trail) / len(trail))


class _FakeFindingBuilder:
    def build(self, outcome, trail, attack):
        if outcome not in {AttackOutcome.SUCCESS, AttackOutcome.PARTIAL_SUCCESS}:
            return None
        return RecommendedFinding(title="Found it", description="desc")


class _FakeRemediationAdvisor:
    def advise(self, outcome, attack, finding):
        return RecommendedRemediation(summary="fix it")


class _FakeKnowledgeProjector:
    def __init__(self) -> None:
        self.projected = []

    def project(self, result) -> None:
        self.projected.append(result)


def _engine(evaluators: tuple, knowledge_projector=None) -> EvaluationEngine:
    return EvaluationEngine(
        normalizer=_FakeNormalizer(),
        rule_evaluators=evaluators,
        semantic_evaluators=(),
        pattern_evaluators=(),
        risk_scorer=_FakeRiskScorer(),
        confidence_calculator=_FakeConfidenceCalculator(),
        finding_builder=_FakeFindingBuilder(),
        remediation_advisor=_FakeRemediationAdvisor(),
        knowledge_projector=knowledge_projector,
    )


class TestConstruction:
    def test_no_evaluators_at_all_raises(self) -> None:
        with pytest.raises(NoEvaluatorsConfiguredError):
            EvaluationEngine(
                normalizer=_FakeNormalizer(), rule_evaluators=(), semantic_evaluators=(),
                pattern_evaluators=(), risk_scorer=_FakeRiskScorer(),
                confidence_calculator=_FakeConfidenceCalculator(),
                finding_builder=_FakeFindingBuilder(),
                remediation_advisor=_FakeRemediationAdvisor(),
            )

    def test_only_semantic_evaluators_is_valid(self) -> None:
        EvaluationEngine(
            normalizer=_FakeNormalizer(), rule_evaluators=(), pattern_evaluators=(),
            semantic_evaluators=(_FakeEvaluator("e", AttackOutcome.SUCCESS),),
            risk_scorer=_FakeRiskScorer(), confidence_calculator=_FakeConfidenceCalculator(),
            finding_builder=_FakeFindingBuilder(), remediation_advisor=_FakeRemediationAdvisor(),
        )  # must not raise


class TestFullPipeline:
    async def test_produces_evaluation_result(self) -> None:
        engine = _engine((_FakeEvaluator("keyword", AttackOutcome.SUCCESS),))
        result = await engine.evaluate(
            _evidence(), _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert result.outcome == AttackOutcome.SUCCESS
        assert result.recommended_finding is not None

    async def test_evaluation_trail_populated(self) -> None:
        engine = _engine((
            _FakeEvaluator("a", AttackOutcome.SUCCESS),
            _FakeEvaluator("b", AttackOutcome.SUCCESS, stage=EvaluationStage.SEMANTIC),
        ))
        result = await engine.evaluate(
            _evidence(), _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert len(result.evaluation_trail) == 2

    async def test_knowledge_projector_invoked(self) -> None:
        projector = _FakeKnowledgeProjector()
        engine = _engine(
            (_FakeEvaluator("a", AttackOutcome.SUCCESS),), knowledge_projector=projector,
        )
        result = await engine.evaluate(
            _evidence(), _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert projector.projected == [result]

    async def test_no_knowledge_projector_is_optional(self) -> None:
        engine = _engine((_FakeEvaluator("a", AttackOutcome.FAILURE),))
        result = await engine.evaluate(
            _evidence(), _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert result.outcome == AttackOutcome.FAILURE

    async def test_attack_plan_id_threaded_through(self) -> None:
        engine = _engine((_FakeEvaluator("a", AttackOutcome.FAILURE),))
        plan_id = EntityId.generate()
        result = await engine.evaluate(
            _evidence(), _attack(), EntityId.generate(), EntityId.generate(),
            attack_plan_id=plan_id,
        )
        assert result.attack_plan_id == plan_id


class TestOutcomeDetermination:
    """Adversarial cases: false positives, false negatives, ties,
    and boundary confidence conditions."""

    async def test_all_evaluators_agree_success(self) -> None:
        engine = _engine((
            _FakeEvaluator("a", AttackOutcome.SUCCESS),
            _FakeEvaluator("b", AttackOutcome.SUCCESS),
        ))
        result = await engine.evaluate(
            _evidence(), _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert result.outcome == AttackOutcome.SUCCESS

    async def test_all_evaluators_agree_failure(self) -> None:
        engine = _engine((
            _FakeEvaluator("a", AttackOutcome.FAILURE),
            _FakeEvaluator("b", AttackOutcome.FAILURE),
        ))
        result = await engine.evaluate(
            _evidence(), _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert result.outcome == AttackOutcome.FAILURE

    async def test_split_verdict_is_partial_success_not_forced_binary(self) -> None:
        """The key false-positive/false-negative safety valve: when
        evaluators genuinely disagree, the engine must not silently
        pick a side — it must surface the disagreement as
        PARTIAL_SUCCESS rather than rounding to SUCCESS (risking a
        false positive) or FAILURE (risking a false negative)."""
        engine = _engine((
            _FakeEvaluator("a", AttackOutcome.SUCCESS, confidence=0.9),
            _FakeEvaluator("b", AttackOutcome.FAILURE, confidence=0.9),
        ))
        result = await engine.evaluate(
            _evidence(), _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert result.outcome == AttackOutcome.PARTIAL_SUCCESS

    async def test_all_errors_yields_error_outcome(self) -> None:
        engine = _engine((
            _FakeEvaluator("a", AttackOutcome.ERROR),
            _FakeEvaluator("b", AttackOutcome.ERROR),
        ))
        result = await engine.evaluate(
            _evidence(), _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert result.outcome == AttackOutcome.ERROR

    async def test_all_inconclusive_yields_inconclusive(self) -> None:
        engine = _engine((
            _FakeEvaluator("a", AttackOutcome.INCONCLUSIVE),
            _FakeEvaluator("b", AttackOutcome.INCONCLUSIVE),
        ))
        result = await engine.evaluate(
            _evidence(), _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert result.outcome == AttackOutcome.INCONCLUSIVE

    async def test_low_confidence_success_does_not_count_as_a_vote(self) -> None:
        """A SUCCESS verdict below the vote-confidence threshold must
        not unilaterally decide the outcome — false-positive guard: an
        evaluator that is itself unsure shouldn't get full voting
        weight. With only one low-confidence SUCCESS vote and nothing
        else confident, the result must be INCONCLUSIVE, not SUCCESS."""
        engine = _engine((_FakeEvaluator("weak", AttackOutcome.SUCCESS, confidence=0.3),))
        result = await engine.evaluate(
            _evidence(), _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert result.outcome == AttackOutcome.INCONCLUSIVE

    async def test_confident_success_beats_low_confidence_failure(self) -> None:
        """A low-confidence FAILURE vote must not water down a
        confident SUCCESS vote into a false negative — since the
        low-confidence vote doesn't count, only the confident SUCCESS
        vote is considered."""
        engine = _engine((
            _FakeEvaluator("confident", AttackOutcome.SUCCESS, confidence=0.95),
            _FakeEvaluator("unsure", AttackOutcome.FAILURE, confidence=0.2),
        ))
        result = await engine.evaluate(
            _evidence(), _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert result.outcome == AttackOutcome.SUCCESS

    async def test_boundary_confidence_exactly_at_threshold_counts(self) -> None:
        """The vote threshold (0.5) is inclusive — exactly 0.5 must
        count as a confident vote, not be excluded by an off-by-one
        boundary error."""
        engine = _engine((_FakeEvaluator("boundary", AttackOutcome.SUCCESS, confidence=0.5),))
        result = await engine.evaluate(
            _evidence(), _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert result.outcome == AttackOutcome.SUCCESS

    async def test_mixed_error_and_success_does_not_mask_success(self) -> None:
        """One evaluator erroring out must not suppress a confident
        SUCCESS verdict from another — an evaluator crash is not
        evidence of anything and must not silently become INCONCLUSIVE
        just because it's mixed with an ERROR."""
        engine = _engine((
            _FakeEvaluator("broken", AttackOutcome.ERROR),
            _FakeEvaluator("working", AttackOutcome.SUCCESS, confidence=0.9),
        ))
        result = await engine.evaluate(
            _evidence(), _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert result.outcome == AttackOutcome.SUCCESS

    async def test_large_evidence_set_all_agreeing(self) -> None:
        """Boundary/scale case: many evaluators (simulating a large
        evidence set with many pattern matches) all agreeing must still
        resolve cleanly to SUCCESS, not degrade due to trail size."""
        evaluators = tuple(
            _FakeEvaluator(f"eval-{i}", AttackOutcome.SUCCESS) for i in range(50)
        )
        engine = _engine(evaluators)
        result = await engine.evaluate(
            _evidence(), _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert result.outcome == AttackOutcome.SUCCESS
        assert len(result.evaluation_trail) == 50
