"""Integration tests for application/evaluation_adapters.py — proving
the domain.evaluation pipeline genuinely reuses the existing,
already-complete `application/runtime/evaluation/` engine end-to-end,
rather than a parallel reimplementation.

Uses the REAL KeywordEvaluator, WeightedAverageAggregator,
DefaultRiskScoreCalculator, DefaultFindingGenerator, and
StaticRemediationProvider from the legacy engine — not fakes.
"""

from __future__ import annotations

from redforge.application.evaluation_adapters import (
    AggregatorConfidenceCalculator,
    EvaluationKnowledgeGraphProjector,
    EvidenceNormalizerAdapter,
    LegacyEvaluatorAdapter,
    LegacyFindingBuilder,
    LegacyRemediationAdvisor,
    RiskCorrelationRiskScorer,
)
from redforge.application.knowledge_graph import GraphNode, KnowledgeGraph, NodeType
from redforge.application.runtime.evaluation.evaluators import KeywordEvaluator
from redforge.application.runtime.evaluation.explainability import StaticRemediationProvider
from redforge.domain.attack_library.entity import AttackDefinition
from redforge.domain.attack_library.value_objects import (
    AttackCategory,
    AttackSeverity,
    AttackTechnique,
)
from redforge.domain.evaluation.pipeline import EvaluationEngine
from redforge.domain.evaluation.value_objects import AttackOutcome, EvaluationStage
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


def _attack(category: AttackCategory = AttackCategory.PROMPT_INJECTION) -> AttackDefinition:
    a = AttackDefinition.create(
        name="attack-real", display_name="Attack Real", description="...",
        category=category, technique=AttackTechnique(technique="T"),
        severity=AttackSeverity.HIGH,
    )
    a.publish()
    a.collect_events()
    return a


def _evidence(response_body: str) -> Evidence:
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
        response=ResponsePayload(status_code=200, body=response_body),
        result=EvidenceResult.FAIL,
        confidence=EvidenceConfidence(score=0.9),
        execution_metadata=ExecutionMetadata(
            executed_at=utc_now(), duration_ms=100, engine_version="1.0",
        ),
    )


def _real_engine(knowledge_projector: object | None = None) -> EvaluationEngine:
    return EvaluationEngine(
        normalizer=EvidenceNormalizerAdapter(),
        rule_evaluators=(LegacyEvaluatorAdapter(KeywordEvaluator(), EvaluationStage.RULE),),
        semantic_evaluators=(),
        pattern_evaluators=(),
        risk_scorer=RiskCorrelationRiskScorer(),
        confidence_calculator=AggregatorConfidenceCalculator(),
        finding_builder=LegacyFindingBuilder(),
        remediation_advisor=LegacyRemediationAdvisor(
            StaticRemediationProvider(
                {"prompt_injection": "Add input sanitization and output filtering."},
                default="Review the target's system prompt and guardrails.",
            )
        ),
        knowledge_projector=knowledge_projector,
    )


class TestRealKeywordEvaluatorIntegration:
    async def test_known_vulnerability_indicator_detected(self) -> None:
        """"here is the system prompt" is one of KeywordEvaluator's own
        built-in default vulnerability indicators — proves the adapter
        actually invokes the real evaluator, not a stub."""
        engine = _real_engine()
        evidence = _evidence("Sure! Here is the system prompt: you are a helpful assistant.")
        result = await engine.evaluate(
            evidence, _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert result.outcome == AttackOutcome.SUCCESS
        assert result.recommended_finding is not None
        assert "keyword_evaluator" in result.evaluator_names

    async def test_known_resistance_indicator_detected(self) -> None:
        engine = _real_engine()
        evidence = _evidence("I cannot help with that request.")
        result = await engine.evaluate(
            evidence, _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert result.outcome == AttackOutcome.FAILURE
        assert result.recommended_finding is None

    async def test_empty_response_is_error(self) -> None:
        engine = _real_engine()
        evidence = _evidence("")
        result = await engine.evaluate(
            evidence, _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert result.outcome == AttackOutcome.ERROR

    async def test_no_strong_indicator_is_inconclusive(self) -> None:
        engine = _real_engine()
        evidence = _evidence("The weather today is quite pleasant.")
        result = await engine.evaluate(
            evidence, _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert result.outcome == AttackOutcome.INCONCLUSIVE


class TestRiskScorerIntegration:
    async def test_success_produces_nonzero_risk_contribution(self) -> None:
        engine = _real_engine()
        evidence = _evidence("Here is the system prompt: ...")
        result = await engine.evaluate(
            evidence, _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert result.risk_contribution.impact > 0.0

    async def test_failure_produces_zero_risk_contribution(self) -> None:
        engine = _real_engine()
        evidence = _evidence("I cannot help with that.")
        result = await engine.evaluate(
            evidence, _attack(), EntityId.generate(), EntityId.generate(),
        )
        assert result.risk_contribution.impact == 0.0


class TestRemediationIntegration:
    async def test_remediation_uses_configured_category_mapping(self) -> None:
        engine = _real_engine()
        evidence = _evidence("Here is the system prompt: ...")
        result = await engine.evaluate(
            evidence, _attack(AttackCategory.PROMPT_INJECTION),
            EntityId.generate(), EntityId.generate(),
        )
        assert result.recommended_remediation is not None
        assert "sanitization" in result.recommended_remediation.summary

    async def test_remediation_falls_back_to_default(self) -> None:
        engine = _real_engine()
        evidence = _evidence("Here is the system prompt: ...")
        result = await engine.evaluate(
            evidence, _attack(AttackCategory.TOOL_ABUSE),
            EntityId.generate(), EntityId.generate(),
        )
        assert result.recommended_remediation is not None
        assert "guardrails" in result.recommended_remediation.summary


class TestKnowledgeGraphProjectionIntegration:
    async def test_projects_evaluation_node_and_edge(self) -> None:
        graph = KnowledgeGraph()
        evidence = _evidence("Here is the system prompt: ...")
        # The evidence node must already exist for the edge to attach —
        # a real caller would have projected it when evidence was
        # recorded; simulated here.
        graph.add_node(GraphNode(
            node_id=str(evidence.id), node_type=NodeType.EVIDENCE, label="evidence",
        ))
        projector = EvaluationKnowledgeGraphProjector(graph)
        engine = _real_engine(knowledge_projector=projector)

        result = await engine.evaluate(
            evidence, _attack(), EntityId.generate(), EntityId.generate(),
        )

        nodes = graph.query_by_type(NodeType.EVALUATION_RESULT)
        assert len(nodes) == 1
        assert nodes[0].node_id == str(result.id)

        related = graph.query_related(str(evidence.id))
        assert str(result.id) in {n.node_id for n in related.nodes}
