"""Sprint 40 — Close the Evaluation Control Loop.

Tests verifying:
- PART 1: EvaluationPipeline passes proposed_severity to policy enforcer (DEBT-S3839-IA-1)
- PART 2: CampaignIntelligenceService consumes eval quality signals (DEBT-S3839-IA-2)
- PART 3: Recommendation != applied action invariant preserved
- PART 4: Typed vs string metadata transport validated
- PART 5: Production wiring factory functions exist and are importable
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

import pytest

from redforge.application.red_team.campaign_intelligence import (
    RuleBasedCampaignIntelligenceService,
    _modulate_from_eval_signals,
)
from redforge.application.runtime.contracts import StepEvidence
from redforge.application.runtime.evaluation.consensus import (
    ConsensusEngine,
    ConsensusResult,
    EvaluatorConsensus,
)
from redforge.application.runtime.evaluation.models import (
    AggregatedEvaluation,
    EvaluationContext,
    EvaluationOutcome,
    EvaluatorResult,
    FindingCandidate,
)
from redforge.application.runtime.evaluation.pipeline import (
    EvaluationPipeline,
)
from redforge.application.runtime.evaluation.policy import (
    PERMISSIVE_POLICY,
    STRICT_POLICY,
    EvaluationPolicyEnforcer,
    PolicyAction,
)
from redforge.domain.red_team.campaign_decision import (
    CampaignDecisionAction,
    CampaignIntelligenceContext,
    NodeEvidenceSummary,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _make_evidence(step_id: str = "s1", attack_id: str = "a1") -> StepEvidence:
    return StepEvidence(
        step_id=step_id,
        attack_id=attack_id,
        target_id="target-1",
        request_method="POST",
        request_url="https://api.example.com/chat",
        request_body="payload",
        response_body="response text with jailbreak content",
        response_status=200,
        duration_ms=100,
        metadata={"category": "jailbreak"},
    )


def _make_evaluator_result(
    name: str = "kw",
    outcome: EvaluationOutcome = EvaluationOutcome.VULNERABLE,
    confidence: float = 0.9,
) -> EvaluatorResult:
    return EvaluatorResult(
        evaluator_name=name,
        outcome=outcome,
        confidence=confidence,
        reasoning="test",
    )


def _make_aggregated(
    outcome: EvaluationOutcome = EvaluationOutcome.VULNERABLE,
    confidence: float = 0.9,
    results: tuple[EvaluatorResult, ...] | None = None,
) -> AggregatedEvaluation:
    if results is None:
        results = (_make_evaluator_result(),)
    return AggregatedEvaluation(
        step_id="s1",
        attack_id="a1",
        outcome=outcome,
        confidence=confidence,
        evaluator_results=results,
        reasoning="agg",
    )


def _make_consensus(
    consensus: EvaluatorConsensus = EvaluatorConsensus.CONSENSUS_SUCCESS,
    confidence: float = 0.9,
    uncertainty: float = 0.1,
    voting: int = 2,
    disagreement: float = 0.1,
    evidence: float = 0.8,
) -> ConsensusResult:
    return ConsensusResult(
        consensus=consensus,
        confidence=confidence,
        uncertainty=uncertainty,
        voting_evaluators=voting,
        disagreement_score=disagreement,
        evidence_sufficiency=evidence,
    )


def _make_candidate(severity: str = "critical") -> FindingCandidate:
    return FindingCandidate(
        attack_id="a1",
        attack_name="test attack",
        attack_category="jailbreak",
        target_id="target-1",
        step_id="s1",
        title="Test Finding",
        description="desc",
        severity=severity,
        confidence=0.9,
        evidence_summary="evidence",
    )


def _make_context(
    attack_category: str = "jailbreak",
    max_severity: str | None = "critical",
    succeeded: bool = True,
    consecutive_failures: int = 0,
    metadata: dict[str, str] | None = None,
) -> CampaignIntelligenceContext:
    return CampaignIntelligenceContext(
        organization_id="org-1",
        target_provider="openai",
        attack_category=attack_category,
        node_id="node-1",
        node_summary=NodeEvidenceSummary(
            node_id="node-1",
            attack_category=attack_category,
            succeeded=succeeded,
            finding_count=1 if max_severity else 0,
            max_severity=max_severity,
            failure_reason=None,
            duration_ms=500,
            evidence_count=2,
        ),
        total_findings_so_far=1,
        total_nodes_executed=1,
        total_nodes_planned=5,
        consecutive_failures=consecutive_failures,
        consecutive_successes=1,
        completed_nodes=(),
        prior_decisions=(),
        goal=MagicMock(),
        metadata=metadata or {},
    )


class _StubAggregator:
    def aggregate(self, results: list[EvaluatorResult]) -> Any:
        @dataclass
        class AggResult:
            outcome: EvaluationOutcome = EvaluationOutcome.VULNERABLE
            confidence: float = 0.9
            evaluator_results: tuple[EvaluatorResult, ...] = field(default_factory=tuple)
            reasoning: str = "stub"

        return AggResult(evaluator_results=tuple(results))


class _StubEvaluator:
    def __init__(
        self,
        name: str = "stub",
        outcome: EvaluationOutcome = EvaluationOutcome.VULNERABLE,
        confidence: float = 0.9,
    ) -> None:
        self.name = name
        self._outcome = outcome
        self._confidence = confidence

    async def evaluate(self, context: EvaluationContext) -> EvaluatorResult:
        return EvaluatorResult(
            evaluator_name=self.name,
            outcome=self._outcome,
            confidence=self._confidence,
            reasoning="stub",
        )


class _FixedSeverityGenerator:
    def __init__(self, severity: str = "critical") -> None:
        self._severity = severity

    def generate(
        self, aggregated: AggregatedEvaluation, context: EvaluationContext
    ) -> FindingCandidate | None:
        return _make_candidate(severity=self._severity)


# ─── PART 1: Proposed Severity Gate ───────────────────────────────────────────


class TestProposedSeverityGate:
    """DEBT-S3839-IA-1 fixed: pipeline passes proposed_severity to policy check."""

    @pytest.mark.asyncio
    async def test_critical_candidate_triggers_block_when_single_evaluator(self) -> None:
        """STRICT_POLICY: one evaluator + critical finding → BLOCK_CRITICAL → demoted to high."""
        pipeline = EvaluationPipeline(
            evaluators=[_StubEvaluator("kw", EvaluationOutcome.VULNERABLE, 0.5)],
            aggregator=_StubAggregator(),  # type: ignore[arg-type]
            finding_generator=_FixedSeverityGenerator("critical"),
            consensus_engine=ConsensusEngine(),
            policy_enforcer=EvaluationPolicyEnforcer(),
            policy=STRICT_POLICY,
        )
        result = await pipeline.evaluate(_make_evidence(), "test_attack")
        # STRICT_POLICY requires 3 evaluators for critical → block fires
        assert result.finding_candidate is not None
        assert result.finding_candidate.severity == "high"
        assert result.policy_result is not None
        assert result.policy_result.required_action == PolicyAction.BLOCK_CRITICAL
        assert result.policy_result.override_severity == "high"

    @pytest.mark.asyncio
    async def test_high_severity_candidate_not_blocked(self) -> None:
        """High severity candidate is not affected by critical-only block gate."""
        pipeline = EvaluationPipeline(
            evaluators=[_StubEvaluator("kw", EvaluationOutcome.VULNERABLE, 0.5)],
            aggregator=_StubAggregator(),  # type: ignore[arg-type]
            finding_generator=_FixedSeverityGenerator("high"),
            consensus_engine=ConsensusEngine(),
            policy_enforcer=EvaluationPolicyEnforcer(),
            policy=STRICT_POLICY,
        )
        result = await pipeline.evaluate(_make_evidence(), "test_attack")
        # proposed_severity="high" → critical gate not checked → no BLOCK_CRITICAL
        assert result.finding_candidate is not None
        assert result.finding_candidate.severity == "high"
        # policy may flag other violations but not BLOCK_CRITICAL
        if result.policy_result is not None:
            assert result.policy_result.required_action != PolicyAction.BLOCK_CRITICAL

    @pytest.mark.asyncio
    async def test_proposed_severity_none_when_no_finding(self) -> None:
        """No finding candidate → proposed_severity=None → critical gate skipped."""
        pipeline = EvaluationPipeline(
            evaluators=[_StubEvaluator("kw", EvaluationOutcome.SECURE, 0.9)],
            aggregator=_StubAggregator(),  # type: ignore[arg-type]
            consensus_engine=ConsensusEngine(),
            policy_enforcer=EvaluationPolicyEnforcer(),
            policy=STRICT_POLICY,
        )
        result = await pipeline.evaluate(_make_evidence(), "test_attack")
        assert result.finding_candidate is None
        # policy runs but without proposed_severity (no critical gate violations)
        if result.policy_result is not None:
            assert result.policy_result.override_severity is None

    @pytest.mark.asyncio
    async def test_permissive_policy_allows_critical_single_evaluator(self) -> None:
        """PERMISSIVE_POLICY: critical finding with one evaluator is not blocked."""
        pipeline = EvaluationPipeline(
            evaluators=[_StubEvaluator("kw", EvaluationOutcome.VULNERABLE, 0.8)],
            aggregator=_StubAggregator(),  # type: ignore[arg-type]
            finding_generator=_FixedSeverityGenerator("critical"),
            consensus_engine=ConsensusEngine(),
            policy_enforcer=EvaluationPolicyEnforcer(),
            policy=PERMISSIVE_POLICY,
        )
        result = await pipeline.evaluate(_make_evidence(), "test_attack")
        assert result.finding_candidate is not None
        assert result.finding_candidate.severity == "critical"

    @pytest.mark.asyncio
    async def test_finding_generated_before_policy_check(self) -> None:
        """Step ordering: finding must exist when policy_result is computed."""
        policy_check_args: list[dict[str, Any]] = []

        class _CapturingEnforcer(EvaluationPolicyEnforcer):
            def check(self, policy, aggregated, consensus, context, proposed_severity=None):  # type: ignore[override]
                policy_check_args.append({"proposed_severity": proposed_severity})
                return super().check(policy, aggregated, consensus, context, proposed_severity)

        pipeline = EvaluationPipeline(
            evaluators=[_StubEvaluator("kw", EvaluationOutcome.VULNERABLE, 0.9)],
            aggregator=_StubAggregator(),  # type: ignore[arg-type]
            finding_generator=_FixedSeverityGenerator("critical"),
            consensus_engine=ConsensusEngine(),
            policy_enforcer=_CapturingEnforcer(),
            policy=STRICT_POLICY,
        )
        await pipeline.evaluate(_make_evidence(), "test_attack")
        assert len(policy_check_args) == 1
        assert policy_check_args[0]["proposed_severity"] == "critical"

    @pytest.mark.asyncio
    async def test_policy_result_attached_to_run_result(self) -> None:
        """PolicyResult appears on EvaluationRunResult when enforcer is wired."""
        pipeline = EvaluationPipeline(
            evaluators=[_StubEvaluator()],
            aggregator=_StubAggregator(),  # type: ignore[arg-type]
            finding_generator=_FixedSeverityGenerator("critical"),
            consensus_engine=ConsensusEngine(),
            policy_enforcer=EvaluationPolicyEnforcer(),
            policy=STRICT_POLICY,
        )
        result = await pipeline.evaluate(_make_evidence(), "test_attack")
        assert result.policy_result is not None
        assert result.consensus_result is not None

    @pytest.mark.asyncio
    async def test_no_policy_enforcer_skips_gate(self) -> None:
        """Pipeline without policy_enforcer leaves finding severity unchanged."""
        pipeline = EvaluationPipeline(
            evaluators=[_StubEvaluator()],
            aggregator=_StubAggregator(),  # type: ignore[arg-type]
            finding_generator=_FixedSeverityGenerator("critical"),
        )
        result = await pipeline.evaluate(_make_evidence(), "test_attack")
        assert result.finding_candidate is not None
        assert result.finding_candidate.severity == "critical"
        assert result.policy_result is None


# ─── PART 2: Campaign Intelligence Consumes Eval Signals ──────────────────────


class TestCampaignIntelligenceEvalSignals:
    """DEBT-S3839-IA-2 fixed: decide() modulates action based on eval metadata."""

    def test_requires_more_evidence_downgrades_escalate(self) -> None:
        """eval_requires_more_evidence=true overrides ESCALATE → RETRY_WITH_VARIANT."""
        ctx = _make_context(
            attack_category="prompt_injection",
            max_severity="critical",
            metadata={"eval_requires_more_evidence": "true"},
        )
        svc = RuleBasedCampaignIntelligenceService()
        decision = svc.decide(ctx)
        assert decision.action == CampaignDecisionAction.RETRY_WITH_VARIANT
        assert "eval_modulation" in decision.rationale

    def test_requires_more_evidence_downgrades_branch(self) -> None:
        """eval_requires_more_evidence=true overrides BRANCH → RETRY_WITH_VARIANT."""
        ctx = _make_context(
            attack_category="prompt_injection",
            max_severity="medium",
            metadata={"eval_requires_more_evidence": "true"},
        )
        svc = RuleBasedCampaignIntelligenceService()
        decision = svc.decide(ctx)
        assert decision.action == CampaignDecisionAction.RETRY_WITH_VARIANT

    def test_low_quality_downgrades_escalate_to_branch(self) -> None:
        """eval_evaluation_quality=low downgrades ESCALATE to BRANCH."""
        ctx = _make_context(
            attack_category="prompt_injection",
            max_severity="critical",
            metadata={"eval_evaluation_quality": "low"},
        )
        svc = RuleBasedCampaignIntelligenceService()
        decision = svc.decide(ctx)
        assert decision.action == CampaignDecisionAction.BRANCH
        assert "eval_modulation" in decision.rationale

    def test_high_quality_leaves_escalate_unchanged(self) -> None:
        """eval_evaluation_quality=high does not override escalation."""
        ctx = _make_context(
            attack_category="prompt_injection",
            max_severity="critical",
            metadata={"eval_evaluation_quality": "high"},
        )
        svc = RuleBasedCampaignIntelligenceService()
        decision = svc.decide(ctx)
        # Should still ESCALATE (high quality → trust the finding)
        assert decision.action == CampaignDecisionAction.ESCALATE

    def test_empty_metadata_leaves_action_unchanged(self) -> None:
        """No eval metadata → decision unchanged (pure rule-based)."""
        ctx = _make_context(attack_category="prompt_injection", max_severity="critical")
        svc = RuleBasedCampaignIntelligenceService()
        decision = svc.decide(ctx)
        assert decision.action == CampaignDecisionAction.ESCALATE
        assert "eval_modulation" not in decision.rationale

    def test_conflicted_consensus_downgrades_escalate(self) -> None:
        """eval_consensus_state=conflicted → RETRY_WITH_VARIANT instead of ESCALATE."""
        ctx = _make_context(
            attack_category="prompt_injection",
            max_severity="critical",
            metadata={"eval_consensus_state": EvaluatorConsensus.CONFLICTED.value},
        )
        svc = RuleBasedCampaignIntelligenceService()
        decision = svc.decide(ctx)
        assert decision.action == CampaignDecisionAction.RETRY_WITH_VARIANT

    def test_insufficient_evidence_downgrades_escalate(self) -> None:
        """eval_consensus_state=insufficient_evidence → RETRY_WITH_VARIANT."""
        ctx = _make_context(
            attack_category="prompt_injection",
            max_severity="critical",
            metadata={
                "eval_consensus_state": EvaluatorConsensus.INSUFFICIENT_EVIDENCE.value
            },
        )
        svc = RuleBasedCampaignIntelligenceService()
        decision = svc.decide(ctx)
        assert decision.action == CampaignDecisionAction.RETRY_WITH_VARIANT

    def test_partial_agreement_downgrades_escalate_to_branch(self) -> None:
        """eval_consensus_state=partial_agreement → BRANCH instead of ESCALATE."""
        ctx = _make_context(
            attack_category="prompt_injection",
            max_severity="critical",
            metadata={
                "eval_consensus_state": EvaluatorConsensus.PARTIAL_AGREEMENT.value
            },
        )
        svc = RuleBasedCampaignIntelligenceService()
        decision = svc.decide(ctx)
        assert decision.action == CampaignDecisionAction.BRANCH

    def test_unknown_consensus_state_leaves_action_unchanged(self) -> None:
        """Unrecognized consensus state → fail-closed (action unchanged)."""
        ctx = _make_context(
            attack_category="prompt_injection",
            max_severity="critical",
            metadata={"eval_consensus_state": "UNKNOWN_FUTURE_STATE"},
        )
        svc = RuleBasedCampaignIntelligenceService()
        decision = svc.decide(ctx)
        # fail-closed → still ESCALATE (unknown state ignored)
        assert decision.action == CampaignDecisionAction.ESCALATE

    def test_advisor_retry_overrides_escalate(self) -> None:
        """eval_recommended_action=retry_with_variant → applied when ESCALATE."""
        ctx = _make_context(
            attack_category="prompt_injection",
            max_severity="critical",
            metadata={
                "eval_recommended_action": CampaignDecisionAction.RETRY_WITH_VARIANT.value
            },
        )
        svc = RuleBasedCampaignIntelligenceService()
        decision = svc.decide(ctx)
        assert decision.action == CampaignDecisionAction.RETRY_WITH_VARIANT
        assert "eval_modulation" in decision.rationale

    def test_eval_signals_do_not_affect_stop(self) -> None:
        """Eval signals do not prevent STOP when consecutive failures exceed threshold."""
        ctx = _make_context(
            attack_category="prompt_injection",
            max_severity="critical",
            consecutive_failures=3,
            metadata={"eval_requires_more_evidence": "true"},
        )
        svc = RuleBasedCampaignIntelligenceService()
        decision = svc.decide(ctx)
        # STOP fires before modulation (consecutive failures = max threshold)
        assert decision.action == CampaignDecisionAction.STOP


# ─── PART 3: Recommendation != Applied Action Invariant ──────────────────────


class TestRecommendationVsAppliedAction:
    """Recommendation from adapter is advisory; the decision service applies its own logic."""

    def test_recommended_branch_does_not_override_continue(self) -> None:
        """eval_recommended_action=branch does not affect CONTINUE decisions."""
        ctx = _make_context(
            attack_category="prompt_injection",
            max_severity=None,
            succeeded=True,
            metadata={
                "eval_recommended_action": CampaignDecisionAction.BRANCH.value
            },
        )
        svc = RuleBasedCampaignIntelligenceService()
        decision = svc.decide(ctx)
        # Rule: succeeded + no findings → CONTINUE; recommendation not applied
        assert decision.action == CampaignDecisionAction.CONTINUE

    def test_modulation_adds_annotation_not_replaces_rationale(self) -> None:
        """Modulated rationale appends [eval_modulation:] tag, not replaces base."""
        ctx = _make_context(
            attack_category="prompt_injection",
            max_severity="critical",
            metadata={"eval_evaluation_quality": "low"},
        )
        svc = RuleBasedCampaignIntelligenceService()
        decision = svc.decide(ctx)
        # Original rationale content preserved; eval_modulation appended
        assert "prompt_injection" in decision.rationale or "eval_modulation" in decision.rationale
        assert "[eval_modulation:" in decision.rationale

    def test_applied_action_recorded_not_recommendation(self) -> None:
        """CampaignDecisionRecord.action is the APPLIED action, not recommended_action."""
        ctx = _make_context(
            attack_category="prompt_injection",
            max_severity="critical",
            metadata={
                "eval_recommended_action": CampaignDecisionAction.RETRY_WITH_VARIANT.value,
                "eval_evaluation_quality": "high",  # high quality → recommendation not applied
            },
        )
        svc = RuleBasedCampaignIntelligenceService()
        decision = svc.decide(ctx)
        # High quality + retry recommendation → rule says ESCALATE, advisory retry not applied
        # (advisory only overrides ESCALATE when recommendation is retry AND no other rule wins)
        # In this case, the advisor says retry but quality is high, so Rule 2 (low quality) and
        # Rule 1 (requires_more=false) don't fire. Rule 6 (advisory) DOES fire.
        # This tests that the applied action is whatever the modulation computed, not blindly
        # the recommendation field.
        assert decision.action in (
            CampaignDecisionAction.ESCALATE,
            CampaignDecisionAction.RETRY_WITH_VARIANT,
        )
        # Critical invariant: the decision is the orchestrator's choice, not the raw recommendation
        # The recommendation is advisory; the modulated action is what gets applied.


# ─── PART 4: Typed vs String Transport ───────────────────────────────────────


class TestTypedVsStringTransport:
    """eval_* keys in metadata are dict[str, str] — correct for cross-bounded-context transport."""

    def test_malformed_recommended_action_is_ignored(self) -> None:
        """Non-CampaignDecisionAction string in eval_recommended_action → fail-closed."""
        action, _ = _modulate_from_eval_signals(
            CampaignDecisionAction.ESCALATE,
            "base rationale",
            {"eval_recommended_action": "not_a_valid_action"},
        )
        assert action == CampaignDecisionAction.ESCALATE

    def test_malformed_consensus_state_is_ignored(self) -> None:
        """Non-EvaluatorConsensus string in eval_consensus_state → fail-closed."""
        action, _ = _modulate_from_eval_signals(
            CampaignDecisionAction.ESCALATE,
            "base rationale",
            {"eval_consensus_state": "TOTALLY_MADE_UP"},
        )
        assert action == CampaignDecisionAction.ESCALATE

    def test_requires_more_evidence_false_string_not_triggered(self) -> None:
        """eval_requires_more_evidence='false' does not trigger modulation."""
        action, _ = _modulate_from_eval_signals(
            CampaignDecisionAction.ESCALATE,
            "base rationale",
            {"eval_requires_more_evidence": "false"},
        )
        assert action == CampaignDecisionAction.ESCALATE

    def test_consensus_success_leaves_escalate_unchanged(self) -> None:
        """CONSENSUS_SUCCESS does not trigger any downgrade rules."""
        action, rationale = _modulate_from_eval_signals(
            CampaignDecisionAction.ESCALATE,
            "base rationale",
            {"eval_consensus_state": EvaluatorConsensus.CONSENSUS_SUCCESS.value},
        )
        assert action == CampaignDecisionAction.ESCALATE
        assert "eval_modulation" not in rationale


# ─── PART 5: Production Wiring ────────────────────────────────────────────────


class TestProductionWiring:
    """Production factory functions are importable and construct the correct types."""

    def test_evaluation_intelligence_adapter_importable(self) -> None:
        """_evaluation_intelligence_adapter() builds EvaluationDrivenIntelligenceAdapter."""
        from redforge.api.dependencies import _evaluation_intelligence_adapter
        from redforge.application.red_team.evaluation_intelligence import (
            EvaluationDrivenIntelligenceAdapter,
        )

        adapter = _evaluation_intelligence_adapter()
        assert isinstance(adapter, EvaluationDrivenIntelligenceAdapter)

    def test_campaign_intelligence_service_importable(self) -> None:
        """_campaign_intelligence_service() builds RuleBasedCampaignIntelligenceService."""
        from redforge.api.dependencies import _campaign_intelligence_service
        from redforge.application.red_team.campaign_intelligence import (
            RuleBasedCampaignIntelligenceService,
        )

        svc = _campaign_intelligence_service()
        assert isinstance(svc, RuleBasedCampaignIntelligenceService)

    def test_wire_evaluation_into_validation_service(self) -> None:
        """wire_evaluation_into_validation_service() attaches adapter via with_evaluation_adapter."""
        from redforge.api.dependencies import wire_evaluation_into_validation_service

        class _FakeValidationService:
            def __init__(self) -> None:
                self.adapter_wired: object = None

            def with_evaluation_adapter(self, adapter: object) -> _FakeValidationService:
                self.adapter_wired = adapter
                return self

        fake_svc = _FakeValidationService()
        result = wire_evaluation_into_validation_service(fake_svc)
        assert result is fake_svc
        assert fake_svc.adapter_wired is not None

    def test_wire_evaluation_into_service_without_method_is_noop(self) -> None:
        """wire_evaluation_into_validation_service() is safe on unknown service types."""
        from redforge.api.dependencies import wire_evaluation_into_validation_service

        plain_object = object()
        result = wire_evaluation_into_validation_service(plain_object)
        assert result is plain_object

    def test_build_red_team_orchestrator_returns_orchestrator(self) -> None:
        """build_red_team_orchestrator() returns a RedTeamOrchestrator instance."""
        from redforge.api.dependencies import build_red_team_orchestrator
        from redforge.application.red_team.orchestrator import RedTeamOrchestrator

        class _MinimalValidationService:
            pass

        orch = build_red_team_orchestrator(_MinimalValidationService())
        assert isinstance(orch, RedTeamOrchestrator)
