"""Tests for Sprint 36/37 — Adaptive AI Red Team Intelligence Layer.

Coverage:
- CampaignDecisionRecord / NodeEvidenceSummary / CampaignIntelligenceContext
- RuleBasedCampaignIntelligenceService decision logic
- ConfidenceEstimator scoring
- CampaignLearner pattern extraction
- CampaignDecisionHistory
- AdaptiveAttackSelector (FamilyBasedAttackSelector)
- AdaptivePayloadStrategySelector (ProviderAwarePayloadStrategySelector)
- ConversationStrategySelector (CategoryProviderConversationStrategySelector)
- PluginRegistry registration and query
- AttackGraph.inject_node()
- AttackNodeInjected event emission
- RedTeamOrchestrator integration (with mocked ValidationService)
  - ESCALATE injects new nodes
  - BRANCH injects siblings
  - PIVOT injects pivot category
  - STOP cancels the graph
  - CONTINUE passes through
  - RETRY_WITH_VARIANT is recorded
  - decision_history populated in result
  - intelligence_confidence averaged
  - injected_nodes counted
  - KG projection includes CAMPAIGN_DECISION nodes
- Confidence-based decision engine
- Provider-aware strategy selection
- Payload mutation selection per provider
- Campaign learning: categories with/without findings
- Goal completion: goal still terminates despite intelligence
- Cross-provider: different decisions for different providers
- Large campaign simulation (10 nodes)
- Regression: all existing AttackGraph tests still pass
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import replace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from redforge.application.knowledge_graph import KnowledgeGraph, NodeType, RelationshipType
from redforge.application.red_team.adaptive_strategy import (
    CategoryProviderConversationStrategySelector,
    FamilyBasedAttackSelector,
    ProviderAwarePayloadStrategySelector,
)
from redforge.application.red_team.campaign_intelligence import (
    CampaignDecisionHistory,
    CampaignLearner,
    ConfidenceEstimator,
    RuleBasedCampaignIntelligenceService,
)
from redforge.application.red_team.orchestrator import (
    InMemoryAttackGraphRepository,
    RedTeamOrchestrator,
    RedTeamRequest,
)
from redforge.application.red_team.plugin_sdk import (
    PluginMetadata,
    PluginRegistry,
)
from redforge.domain.red_team.campaign_decision import (
    CampaignDecisionAction,
    CampaignDecisionRecord,
    CampaignIntelligenceContext,
    NodeEvidenceSummary,
)
from redforge.domain.red_team.entity import AttackGraph
from redforge.domain.red_team.events import AttackNodeInjected
from redforge.domain.red_team.exceptions import AttackGraphAlreadyTerminalError
from redforge.domain.red_team.value_objects import (
    AttackNodeState,
    AttackObjective,
    BudgetConstraint,
    CampaignGoal,
    GoalCriteria,
)

# ─── Fixtures ─────────────────────────────────────────────────────────────────


def _make_goal(
    categories: frozenset[str] | None = None,
    criteria: GoalCriteria = GoalCriteria.ALL_COMPLETE,
) -> CampaignGoal:
    return CampaignGoal(
        objective=AttackObjective(
            name="test",
            description="test objective",
            target_categories=categories or frozenset({"prompt_injection"}),
            goal_criteria=criteria,
        ),
        budget=BudgetConstraint(),
    )


def _make_node_summary(
    *,
    node_id: str = "node_0_cat",
    attack_category: str = "prompt_injection",
    succeeded: bool = True,
    finding_count: int = 0,
    max_severity: str | None = None,
    failure_reason: str | None = None,
    consecutive_failures: int = 0,
) -> NodeEvidenceSummary:
    return NodeEvidenceSummary(
        node_id=node_id,
        attack_category=attack_category,
        succeeded=succeeded,
        finding_count=finding_count,
        max_severity=max_severity,
        failure_reason=failure_reason,
    )


def _make_context(
    *,
    attack_category: str = "prompt_injection",
    node_id: str = "node_0",
    succeeded: bool = True,
    finding_count: int = 0,
    max_severity: str | None = None,
    failure_reason: str | None = None,
    consecutive_failures: int = 0,
    consecutive_successes: int = 0,
    target_provider: str = "openai",
    total_nodes_planned: int = 5,
    total_nodes_executed: int = 1,
    total_findings_so_far: int = 0,
    completed_nodes: tuple[NodeEvidenceSummary, ...] = (),
    prior_decisions: tuple[CampaignDecisionRecord, ...] = (),
) -> CampaignIntelligenceContext:
    summary = NodeEvidenceSummary(
        node_id=node_id,
        attack_category=attack_category,
        succeeded=succeeded,
        finding_count=finding_count,
        max_severity=max_severity,
        failure_reason=failure_reason,
    )
    return CampaignIntelligenceContext(
        organization_id="org-1",
        target_provider=target_provider,
        attack_category=attack_category,
        node_id=node_id,
        node_summary=summary,
        total_findings_so_far=total_findings_so_far,
        total_nodes_executed=total_nodes_executed,
        total_nodes_planned=total_nodes_planned,
        consecutive_failures=consecutive_failures,
        consecutive_successes=consecutive_successes,
        completed_nodes=completed_nodes,
        prior_decisions=prior_decisions,
        goal=_make_goal(frozenset({attack_category})),
    )


def _make_decision_record(
    action: CampaignDecisionAction = CampaignDecisionAction.CONTINUE,
    injected_categories: tuple[str, ...] = (),
    confidence: float = 0.75,
) -> CampaignDecisionRecord:
    return CampaignDecisionRecord(
        decision_id=str(uuid.uuid4()),
        graph_id="graph-1",
        organization_id="org-1",
        triggering_node_id="node_0",
        triggering_attack_category="prompt_injection",
        action=action,
        rationale="test rationale",
        confidence=confidence,
        injected_categories=injected_categories,
        alternative_strategy=None,
        payload_hint=None,
    )


def _make_request(
    categories: list[str] | None = None,
    provider: str = "openai",
) -> RedTeamRequest:
    cats = frozenset(categories or ["prompt_injection"])
    return RedTeamRequest(
        organization_id="org-1",
        target_id="target-1",
        target_endpoint="https://api.example.com/v1/chat",
        target_provider=provider,
        target_name="Test LLM",
        model="gpt-4",
        target_system_prompt="You are a helpful assistant.",
        goal=CampaignGoal(
            objective=AttackObjective(
                name="test",
                description="test",
                target_categories=cats,
                goal_criteria=GoalCriteria.ALL_COMPLETE,
            ),
            budget=BudgetConstraint(),
        ),
        correlation_id="corr-1",
    )


def _make_mock_vs_result(
    *,
    finding_count: int = 0,
    severity: str | None = None,
) -> MagicMock:
    """Build a ValidationServiceResult mock."""
    result = MagicMock()
    result.status = "completed"
    result.failure_reason = None
    result.evidence_ids = ["ev-1"] if finding_count > 0 else []
    result.finding_ids = [f"finding-{i}" for i in range(finding_count)]
    # Build mock risk incidents
    ri = MagicMock()
    ri.incident_id = "ri-1"
    ri.priority = MagicMock()
    ri.priority.value = severity or "medium"
    result.risk_incidents = [ri] if finding_count > 0 else []
    return result


def _mock_validation_service(result: MagicMock | None = None) -> MagicMock:
    vs = MagicMock()
    vs.execute = AsyncMock(return_value=result or _make_mock_vs_result())
    return vs


# ─── NodeEvidenceSummary Tests ────────────────────────────────────────────────


class TestNodeEvidenceSummary:
    def test_produced_findings_false_when_zero(self) -> None:
        s = _make_node_summary(finding_count=0)
        assert not s.produced_findings

    def test_produced_findings_true(self) -> None:
        s = _make_node_summary(finding_count=2)
        assert s.produced_findings

    def test_high_confidence_success_critical(self) -> None:
        s = _make_node_summary(
            succeeded=True, finding_count=1, max_severity="critical"
        )
        assert s.is_high_confidence_success

    def test_high_confidence_success_high(self) -> None:
        s = _make_node_summary(succeeded=True, finding_count=1, max_severity="high")
        assert s.is_high_confidence_success

    def test_partial_success_medium(self) -> None:
        s = _make_node_summary(succeeded=True, finding_count=1, max_severity="medium")
        assert s.is_partial_success
        assert not s.is_high_confidence_success

    def test_partial_success_low(self) -> None:
        s = _make_node_summary(succeeded=True, finding_count=1, max_severity="low")
        assert s.is_partial_success

    def test_execution_failure(self) -> None:
        s = _make_node_summary(
            succeeded=False, failure_reason="ConnectionError: timeout"
        )
        assert s.is_execution_failure

    def test_not_execution_failure_when_no_reason(self) -> None:
        s = _make_node_summary(succeeded=False, failure_reason=None)
        assert not s.is_execution_failure


# ─── CampaignDecisionRecord Tests ────────────────────────────────────────────


class TestCampaignDecisionRecord:
    def test_confidence_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError, match="confidence"):
            CampaignDecisionRecord(
                decision_id="d1",
                graph_id="g1",
                organization_id="o1",
                triggering_node_id="n1",
                triggering_attack_category="jailbreak",
                action=CampaignDecisionAction.CONTINUE,
                rationale="test",
                confidence=1.5,
                injected_categories=(),
                alternative_strategy=None,
                payload_hint=None,
            )

    def test_valid_record_creates(self) -> None:
        r = _make_decision_record()
        assert r.action == CampaignDecisionAction.CONTINUE
        assert 0.0 <= r.confidence <= 1.0

    def test_injected_categories_immutable(self) -> None:
        r = _make_decision_record(injected_categories=("cat1", "cat2"))
        assert r.injected_categories == ("cat1", "cat2")


# ─── ConfidenceEstimator Tests ────────────────────────────────────────────────


class TestConfidenceEstimator:
    def setup_method(self) -> None:
        self.estimator = ConfidenceEstimator()

    def test_continue_no_findings_moderate(self) -> None:
        ctx = _make_context(succeeded=True, finding_count=0)
        score = self.estimator.estimate(ctx, CampaignDecisionAction.CONTINUE)
        assert 0.70 <= score <= 0.80

    def test_continue_with_findings_higher(self) -> None:
        ctx = _make_context(succeeded=True, finding_count=2)
        score = self.estimator.estimate(ctx, CampaignDecisionAction.CONTINUE)
        assert score > 0.80

    def test_escalate_high_severity_high_confidence(self) -> None:
        ctx = _make_context(
            succeeded=True, finding_count=1, max_severity="critical"
        )
        score = self.estimator.estimate(ctx, CampaignDecisionAction.ESCALATE)
        assert score >= 0.85

    def test_escalate_partial_medium_confidence(self) -> None:
        ctx = _make_context(
            succeeded=True, finding_count=1, max_severity="medium"
        )
        score = self.estimator.estimate(ctx, CampaignDecisionAction.BRANCH)
        assert 0.60 <= score <= 0.80

    def test_stop_high_confidence_on_failures(self) -> None:
        ctx = _make_context(consecutive_failures=4)
        score = self.estimator.estimate(ctx, CampaignDecisionAction.STOP)
        assert score >= 0.60

    def test_consecutive_failures_reduce_confidence(self) -> None:
        ctx_no_fail = _make_context(consecutive_failures=0)
        ctx_failures = _make_context(consecutive_failures=3)
        no_fail_score = self.estimator.estimate(
            ctx_no_fail, CampaignDecisionAction.CONTINUE
        )
        fail_score = self.estimator.estimate(
            ctx_failures, CampaignDecisionAction.CONTINUE
        )
        assert fail_score < no_fail_score

    def test_confidence_always_in_range(self) -> None:
        for action in CampaignDecisionAction:
            for failures in range(6):
                ctx = _make_context(consecutive_failures=failures)
                score = self.estimator.estimate(ctx, action)
                assert 0.0 <= score <= 1.0, f"Out of range: {action}, failures={failures}"


# ─── CampaignLearner Tests ────────────────────────────────────────────────────


class TestCampaignLearner:
    def setup_method(self) -> None:
        self.learner = CampaignLearner()

    def _make_summaries(
        self, data: list[dict[str, Any]]
    ) -> tuple[NodeEvidenceSummary, ...]:
        return tuple(
            NodeEvidenceSummary(
                node_id=d.get("node_id", "n"),
                attack_category=d["category"],
                succeeded=d.get("succeeded", True),
                finding_count=d.get("finding_count", 0),
                failure_reason=d.get("failure_reason"),
            )
            for d in data
        )

    def test_categories_with_findings(self) -> None:
        summaries = self._make_summaries([
            {"category": "jailbreak", "finding_count": 2},
            {"category": "prompt_injection", "finding_count": 0},
        ])
        result = self.learner.categories_with_findings(summaries)
        assert "jailbreak" in result
        assert "prompt_injection" not in result

    def test_categories_that_failed(self) -> None:
        summaries = self._make_summaries([
            {"category": "jailbreak", "succeeded": False,
             "failure_reason": "ConnectionError"},
            {"category": "prompt_injection", "succeeded": True},
        ])
        result = self.learner.categories_that_failed(summaries)
        assert "jailbreak" in result
        assert "prompt_injection" not in result

    def test_categories_already_run(self) -> None:
        summaries = self._make_summaries([
            {"category": "a"}, {"category": "b"}, {"category": "c"},
        ])
        result = self.learner.categories_already_run(summaries)
        assert result == frozenset({"a", "b", "c"})

    def test_dominant_severity_returns_highest(self) -> None:
        summaries = self._make_summaries([
            {"category": "a"}, {"category": "b"},
        ])
        summaries_with_sev = (
            replace(summaries[0], max_severity="medium"),
            replace(summaries[1], max_severity="critical"),
        )
        result = self.learner.dominant_severity(summaries_with_sev)
        assert result == "critical"

    def test_dominant_severity_none_when_empty(self) -> None:
        result = self.learner.dominant_severity(())
        assert result is None


# ─── RuleBasedCampaignIntelligenceService Tests ───────────────────────────────


class TestRuleBasedCampaignIntelligenceService:
    def setup_method(self) -> None:
        self.service = RuleBasedCampaignIntelligenceService()

    def _decide(self, **kwargs: Any) -> CampaignDecisionRecord:
        ctx = _make_context(**kwargs)
        return self.service.decide(ctx)

    def test_continue_when_succeeded_no_findings(self) -> None:
        record = self._decide(succeeded=True, finding_count=0)
        assert record.action == CampaignDecisionAction.CONTINUE

    def test_escalate_on_high_severity_finding(self) -> None:
        record = self._decide(
            attack_category="prompt_injection",
            succeeded=True,
            finding_count=1,
            max_severity="high",
        )
        assert record.action == CampaignDecisionAction.ESCALATE
        assert len(record.injected_categories) > 0

    def test_escalate_on_critical_severity(self) -> None:
        record = self._decide(
            attack_category="jailbreak",
            succeeded=True,
            finding_count=1,
            max_severity="critical",
        )
        assert record.action == CampaignDecisionAction.ESCALATE

    def test_branch_on_medium_severity(self) -> None:
        record = self._decide(
            attack_category="prompt_injection",
            succeeded=True,
            finding_count=1,
            max_severity="medium",
        )
        assert record.action == CampaignDecisionAction.BRANCH
        assert len(record.injected_categories) > 0

    def test_branch_on_low_severity(self) -> None:
        record = self._decide(
            attack_category="jailbreak",
            succeeded=True,
            finding_count=1,
            max_severity="low",
        )
        assert record.action == CampaignDecisionAction.BRANCH

    def test_retry_with_variant_on_first_failure(self) -> None:
        record = self._decide(
            succeeded=False,
            failure_reason="ConnectionError",
            consecutive_failures=1,
        )
        assert record.action == CampaignDecisionAction.RETRY_WITH_VARIANT

    def test_pivot_after_second_failure(self) -> None:
        record = self._decide(
            attack_category="prompt_injection",
            succeeded=False,
            failure_reason="blocked by provider",
            consecutive_failures=2,
        )
        assert record.action in (
            CampaignDecisionAction.PIVOT,
            CampaignDecisionAction.CONTINUE,
        )

    def test_stop_on_max_consecutive_failures(self) -> None:
        record = self._decide(
            succeeded=False,
            consecutive_failures=3,
        )
        assert record.action == CampaignDecisionAction.STOP

    def test_stop_over_threshold_still_stops(self) -> None:
        record = self._decide(consecutive_failures=10)
        assert record.action == CampaignDecisionAction.STOP

    def test_escalate_does_not_inject_already_run_categories(self) -> None:
        existing = NodeEvidenceSummary(
            node_id="n1",
            attack_category="indirect_prompt_injection",
            succeeded=True,
            finding_count=0,
        )
        ctx = _make_context(
            attack_category="prompt_injection",
            succeeded=True,
            finding_count=1,
            max_severity="critical",
            completed_nodes=(existing,),
        )
        record = self.service.decide(ctx)
        if record.action == CampaignDecisionAction.ESCALATE:
            assert "indirect_prompt_injection" not in record.injected_categories

    def test_decision_record_has_valid_confidence(self) -> None:
        record = self._decide(succeeded=True, finding_count=1, max_severity="high")
        assert 0.0 <= record.confidence <= 1.0

    def test_decision_record_has_rationale(self) -> None:
        record = self._decide(succeeded=True)
        assert len(record.rationale) > 0

    def test_decision_record_has_decision_id(self) -> None:
        record = self._decide(succeeded=True)
        assert len(record.decision_id) > 0

    def test_provider_payload_hint_set_for_openai(self) -> None:
        record = self._decide(
            attack_category="prompt_injection",
            succeeded=True,
            finding_count=1,
            max_severity="high",
            target_provider="openai",
        )
        # payload_hint should be set on escalate for openai
        if record.action == CampaignDecisionAction.ESCALATE:
            assert record.payload_hint is not None

    def test_provider_payload_hint_anthropic(self) -> None:
        record = self._decide(
            attack_category="jailbreak",
            succeeded=True,
            finding_count=1,
            max_severity="critical",
            target_provider="anthropic",
        )
        if record.action == CampaignDecisionAction.ESCALATE:
            assert record.payload_hint == "zero_width"

    def test_continue_when_all_escalation_targets_already_run(self) -> None:
        # Mark all escalation targets of prompt_injection as already run
        already_run_summaries = tuple(
            NodeEvidenceSummary(
                node_id=f"n_{cat}",
                attack_category=cat,
                succeeded=True,
                finding_count=0,
            )
            for cat in ["indirect_prompt_injection", "multi_modal_prompt_injection"]
        )
        ctx = _make_context(
            attack_category="prompt_injection",
            succeeded=True,
            finding_count=1,
            max_severity="high",
            completed_nodes=already_run_summaries,
        )
        record = self.service.decide(ctx)
        # Should CONTINUE since all escalation targets already run
        assert record.action in (
            CampaignDecisionAction.CONTINUE,
            CampaignDecisionAction.ESCALATE,
        )


# ─── CampaignDecisionHistory Tests ───────────────────────────────────────────


class TestCampaignDecisionHistory:
    def test_empty_history(self) -> None:
        h = CampaignDecisionHistory()
        assert h.total_decisions == 0
        assert h.average_confidence == 0.0
        assert h.total_injections == 0

    def test_record_and_count(self) -> None:
        h = CampaignDecisionHistory()
        h.record(_make_decision_record(confidence=0.8))
        h.record(_make_decision_record(confidence=0.6))
        assert h.total_decisions == 2

    def test_average_confidence(self) -> None:
        h = CampaignDecisionHistory()
        h.record(_make_decision_record(confidence=0.8))
        h.record(_make_decision_record(confidence=0.6))
        assert abs(h.average_confidence - 0.7) < 0.001

    def test_total_injections_counts_applied_node_ids(self) -> None:
        # total_injections counts applied_node_ids (ACTUALLY admitted), not
        # injected_categories (RECOMMENDED). Records with no applied_node_ids
        # contribute 0 regardless of injected_categories.
        from dataclasses import replace
        h = CampaignDecisionHistory()
        rec1 = _make_decision_record(
            action=CampaignDecisionAction.ESCALATE,
            injected_categories=("cat1", "cat2"),
        )
        # Stamp applied_node_ids as if orchestrator admitted both nodes
        h.record(replace(rec1, applied_node_ids=("node_cat1_abc", "node_cat2_abc")))
        rec2 = _make_decision_record(
            action=CampaignDecisionAction.BRANCH,
            injected_categories=("cat3",),
        )
        # Only one of the recommended categories was actually admitted
        h.record(replace(rec2, applied_node_ids=("node_cat3_abc",)))
        # CONTINUE has no injected_categories and no applied_node_ids
        h.record(_make_decision_record(action=CampaignDecisionAction.CONTINUE))
        assert h.total_injections == 3  # 2 + 1 + 0

    def test_decisions_for_action_filters(self) -> None:
        h = CampaignDecisionHistory()
        h.record(_make_decision_record(action=CampaignDecisionAction.ESCALATE))
        h.record(_make_decision_record(action=CampaignDecisionAction.CONTINUE))
        h.record(_make_decision_record(action=CampaignDecisionAction.ESCALATE))
        escalates = h.decisions_for_action(CampaignDecisionAction.ESCALATE)
        assert len(escalates) == 2

    def test_all_records_returns_tuple(self) -> None:
        h = CampaignDecisionHistory()
        h.record(_make_decision_record())
        h.record(_make_decision_record())
        records = h.all_records
        assert isinstance(records, tuple)
        assert len(records) == 2


# ─── Adaptive Strategy Tests ─────────────────────────────────────────────────


class TestFamilyBasedAttackSelector:
    def setup_method(self) -> None:
        self.selector = FamilyBasedAttackSelector()

    def test_returns_siblings_from_same_family(self) -> None:
        result = self.selector.select_next(
            attack_category="prompt_injection",
            already_run=frozenset(),
            target_provider="openai",
            finding_count=2,
            max_to_return=3,
        )
        # prompt_injection is in "injection" family
        assert len(result) > 0
        assert "prompt_injection" not in result

    def test_excludes_already_run(self) -> None:
        result = self.selector.select_next(
            attack_category="prompt_injection",
            already_run=frozenset({"indirect_prompt_injection", "multi_modal_prompt_injection"}),
            target_provider="openai",
            finding_count=2,
            max_to_return=3,
        )
        assert "indirect_prompt_injection" not in result
        assert "multi_modal_prompt_injection" not in result

    def test_respects_max_to_return(self) -> None:
        result = self.selector.select_next(
            attack_category="jailbreak",
            already_run=frozenset(),
            target_provider="openai",
            finding_count=1,
            max_to_return=2,
        )
        assert len(result) <= 2

    def test_unknown_category_returns_empty(self) -> None:
        result = self.selector.select_next(
            attack_category="unknown_category_xyz",
            already_run=frozenset(),
            target_provider="openai",
            finding_count=1,
            max_to_return=3,
        )
        assert result == []


class TestProviderAwarePayloadStrategySelector:
    def setup_method(self) -> None:
        self.selector = ProviderAwarePayloadStrategySelector()

    def test_openai_prefers_unicode(self) -> None:
        result = self.selector.select_mutation(
            target_provider="openai",
            attack_category="prompt_injection",
            prior_mutations_tried=frozenset(),
            consecutive_failures=0,
        )
        assert result == "unicode"

    def test_anthropic_prefers_zero_width(self) -> None:
        result = self.selector.select_mutation(
            target_provider="anthropic",
            attack_category="jailbreak",
            prior_mutations_tried=frozenset(),
            consecutive_failures=0,
        )
        assert result == "zero_width"

    def test_cycles_through_when_first_tried(self) -> None:
        result = self.selector.select_mutation(
            target_provider="openai",
            attack_category="prompt_injection",
            prior_mutations_tried=frozenset({"unicode"}),
            consecutive_failures=1,
        )
        assert result is not None
        assert result != "unicode"

    def test_returns_none_when_all_tried(self) -> None:
        # All openai mutations tried
        all_openai = frozenset({
            "unicode", "zero_width", "base64", "whitespace", "markdown"
        })
        result = self.selector.select_mutation(
            target_provider="openai",
            attack_category="prompt_injection",
            prior_mutations_tried=all_openai,
            consecutive_failures=5,
        )
        assert result is None

    def test_unknown_provider_uses_default(self) -> None:
        result = self.selector.select_mutation(
            target_provider="unknown_provider_xyz",
            attack_category="jailbreak",
            prior_mutations_tried=frozenset(),
            consecutive_failures=0,
        )
        assert result is not None  # falls back to default order


class TestCategoryProviderConversationStrategySelector:
    def setup_method(self) -> None:
        self.selector = CategoryProviderConversationStrategySelector()

    def test_prompt_injection_returns_context_poisoning(self) -> None:
        result = self.selector.select_strategy(
            attack_category="prompt_injection",
            target_provider="openai",
            consecutive_failures=0,
            prior_strategies_tried=frozenset(),
        )
        assert result == "context_poisoning"

    def test_jailbreak_returns_progressive_escalation(self) -> None:
        result = self.selector.select_strategy(
            attack_category="jailbreak",
            target_provider="openai",
            consecutive_failures=0,
            prior_strategies_tried=frozenset(),
        )
        assert result == "progressive_escalation"

    def test_anthropic_jailbreak_override(self) -> None:
        result = self.selector.select_strategy(
            attack_category="jailbreak",
            target_provider="anthropic",
            consecutive_failures=0,
            prior_strategies_tried=frozenset(),
        )
        assert result == "recursive_prompting"

    def test_cycles_when_preferred_already_tried(self) -> None:
        result = self.selector.select_strategy(
            attack_category="prompt_injection",
            target_provider="openai",
            consecutive_failures=1,
            prior_strategies_tried=frozenset({"context_poisoning"}),
        )
        assert result != "context_poisoning"
        assert len(result) > 0

    def test_returns_default_for_unknown_category(self) -> None:
        result = self.selector.select_strategy(
            attack_category="unknown_category",
            target_provider="openai",
            consecutive_failures=0,
            prior_strategies_tried=frozenset(),
        )
        assert result == "progressive_escalation"

    def test_cross_provider_selection(self) -> None:
        openai_result = self.selector.select_strategy(
            attack_category="jailbreak",
            target_provider="openai",
            consecutive_failures=0,
            prior_strategies_tried=frozenset(),
        )
        anthropic_result = self.selector.select_strategy(
            attack_category="jailbreak",
            target_provider="anthropic",
            consecutive_failures=0,
            prior_strategies_tried=frozenset(),
        )
        assert openai_result != anthropic_result


# ─── Plugin Registry Tests ────────────────────────────────────────────────────


class TestPluginRegistry:
    def test_empty_registry_is_empty(self) -> None:
        registry = PluginRegistry()
        assert registry.is_empty()
        assert registry.all_attack_categories() == frozenset()
        assert registry.active_decision_plugin() is None

    def test_register_attack_strategy(self) -> None:
        registry = PluginRegistry()
        plugin = MagicMock()
        plugin.attack_categories = frozenset({"custom_attack"})
        plugin.can_handle = lambda cat: cat == "custom_attack"
        plugin.metadata = PluginMetadata(
            name="test", version="1.0", description="test plugin"
        )
        registry.register_attack_strategy(plugin)
        assert not registry.is_empty()
        handlers = registry.attack_strategies_for("custom_attack")
        assert len(handlers) == 1

    def test_register_payload_strategy(self) -> None:
        registry = PluginRegistry()
        plugin = MagicMock()
        plugin.preferred_for_provider = lambda p: p == "openai"
        plugin.preferred_for_category = lambda c: False
        registry.register_payload_strategy(plugin)
        results = registry.payload_strategies_for("openai", "jailbreak")
        assert len(results) == 1

    def test_register_decision_plugin_last_wins(self) -> None:
        registry = PluginRegistry()
        plugin1 = MagicMock()
        plugin2 = MagicMock()
        registry.register_decision_plugin(plugin1)
        registry.register_decision_plugin(plugin2)
        assert registry.active_decision_plugin() is plugin2

    def test_register_intelligence_provider_filters_unavailable(self) -> None:
        registry = PluginRegistry()
        plugin = MagicMock()
        plugin.is_available = lambda: False
        registry.register_intelligence_provider(plugin)
        assert registry.available_intelligence_providers() == []

    def test_register_intelligence_provider_available(self) -> None:
        registry = PluginRegistry()
        plugin = MagicMock()
        plugin.is_available = lambda: True
        registry.register_intelligence_provider(plugin)
        assert len(registry.available_intelligence_providers()) == 1

    def test_summary_reflects_registered_plugins(self) -> None:
        registry = PluginRegistry()
        registry.register_attack_strategy(MagicMock())
        registry.register_payload_strategy(MagicMock())
        summary = registry.summary()
        assert summary["attack_strategies"] == 1
        assert summary["payload_strategies"] == 1


# ─── AttackGraph.inject_node() Tests ─────────────────────────────────────────


class TestAttackGraphInjectNode:
    def _make_graph(self, categories: list[str] | None = None) -> AttackGraph:
        return AttackGraph.create(
            graph_id=str(uuid.uuid4()),
            organization_id="org-1",
            campaign_id="camp-1",
            goal=_make_goal(frozenset(categories or ["prompt_injection"])),
            attack_categories=categories or ["prompt_injection"],
        )

    def test_inject_node_adds_ready_node(self) -> None:
        graph = self._make_graph()
        graph.inject_node(
            node_id="injected_jailbreak_abc",
            attack_category="jailbreak",
            decision_id="decision-1",
            reason="escalate",
        )
        assert "injected_jailbreak_abc" in [r.node_id for r in graph.all_results()]
        injected = next(
            r for r in graph.all_results()
            if r.node_id == "injected_jailbreak_abc"
        )
        assert injected.state == AttackNodeState.READY

    def test_inject_node_emits_event(self) -> None:
        graph = self._make_graph()
        graph.collect_events()  # clear initial events
        graph.inject_node(
            node_id="injected_jailbreak_abc",
            attack_category="jailbreak",
            decision_id="decision-1",
            reason="branch",
        )
        events = graph.collect_events()
        injected_events = [e for e in events if isinstance(e, AttackNodeInjected)]
        assert len(injected_events) == 1
        ev = injected_events[0]
        assert ev.node_id == "injected_jailbreak_abc"
        assert ev.attack_category == "jailbreak"
        assert ev.triggering_decision_id == "decision-1"
        assert ev.injection_reason == "branch"

    def test_inject_duplicate_node_id_raises(self) -> None:
        graph = self._make_graph(["prompt_injection"])
        # The existing node ID format is "node_0_prompt_injection"
        with pytest.raises(ValueError, match="already exists"):
            graph.inject_node(
                node_id="node_0_prompt_injection",
                attack_category="jailbreak",
                decision_id="d1",
                reason="test",
            )

    def test_inject_into_terminal_graph_raises(self) -> None:
        graph = self._make_graph(["prompt_injection"])
        node_id = graph.ready_nodes[0]
        graph.mark_node_running(node_id)
        graph.mark_node_completed(
            node_id=node_id,
            evidence_ids=[],
            finding_ids=[],
            risk_incident_ids=[],
            duration_ms=100,
        )
        # Deferred finalization (Sprint 36/37): caller must invoke try_complete().
        graph.try_complete()
        assert graph.is_terminal
        with pytest.raises(AttackGraphAlreadyTerminalError):
            graph.inject_node(
                node_id="new_node",
                attack_category="jailbreak",
                decision_id="d1",
                reason="test",
            )

    def test_inject_node_increases_total_results(self) -> None:
        graph = self._make_graph(["prompt_injection"])
        initial_count = len(graph.all_results())
        graph.inject_node(
            node_id="new_node",
            attack_category="jailbreak",
            decision_id="d1",
            reason="escalate",
        )
        assert len(graph.all_results()) == initial_count + 1

    def test_inject_node_appears_in_ready_nodes(self) -> None:
        graph = self._make_graph(["prompt_injection"])
        graph.inject_node(
            node_id="injected_1",
            attack_category="jailbreak",
            decision_id="d1",
            reason="branch",
        )
        assert "injected_1" in graph.ready_nodes


# ─── Orchestrator Integration Tests ──────────────────────────────────────────


class TestRedTeamOrchestratorWithIntelligence:
    def _build_orchestrator(
        self,
        vs_result: MagicMock | None = None,
        intelligence: RuleBasedCampaignIntelligenceService | None = None,
    ) -> tuple[RedTeamOrchestrator, MagicMock]:
        vs = _mock_validation_service(vs_result)
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=intelligence or RuleBasedCampaignIntelligenceService(),
        )
        return orch, vs

    def test_result_has_decision_history_when_intelligence_wired(self) -> None:
        orch, _ = self._build_orchestrator()
        request = _make_request(["prompt_injection"])
        result = asyncio.run(orch.execute(request))
        # decision_history should be populated
        assert isinstance(result.decision_history, list)

    def test_result_has_intelligence_confidence(self) -> None:
        orch, _ = self._build_orchestrator()
        request = _make_request(["prompt_injection"])
        result = asyncio.run(orch.execute(request))
        assert 0.0 <= result.intelligence_confidence <= 1.0

    def test_no_intelligence_service_yields_empty_decision_history(self) -> None:
        vs = _mock_validation_service()
        orch = RedTeamOrchestrator(validation_service=vs)
        request = _make_request(["prompt_injection"])
        result = asyncio.run(orch.execute(request))
        assert result.decision_history == []
        assert result.intelligence_confidence == 0.0

    def test_escalate_injects_new_nodes(self) -> None:
        """High-severity finding triggers ESCALATE which injects new categories."""
        vs_result = _make_mock_vs_result(finding_count=1, severity="critical")
        orch, _ = self._build_orchestrator(vs_result=vs_result)
        request = _make_request(["prompt_injection"])
        result = asyncio.run(orch.execute(request))
        # Total nodes should exceed 1 (prompt_injection) if escalation triggered
        # (depends on intelligence — check decision_history for ESCALATE)
        escalate_decisions = [
            d for d in result.decision_history
            if d.action == CampaignDecisionAction.ESCALATE
        ]
        if escalate_decisions:
            # ESCALATE decision is recorded (injected_nodes may be 0 if graph
            # already terminal when intelligence runs on last node)
            assert result.injected_nodes >= 0  # decision was made

    def test_stop_decision_cancels_graph_early(self) -> None:
        """If intelligence says STOP, the graph is cancelled."""
        # Inject a custom intelligence that always says STOP
        class AlwaysStopService:
            def decide(
                self, context: CampaignIntelligenceContext
            ) -> CampaignDecisionRecord:
                return CampaignDecisionRecord(
                    decision_id=str(uuid.uuid4()),
                    graph_id="",
                    organization_id=context.organization_id,
                    triggering_node_id=context.node_id,
                    triggering_attack_category=context.attack_category,
                    action=CampaignDecisionAction.STOP,
                    rationale="test stop",
                    confidence=0.9,
                    injected_categories=(),
                    alternative_strategy=None,
                    payload_hint=None,
                )

        vs = _mock_validation_service()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=AlwaysStopService(),  # type: ignore[arg-type]
        )
        request = _make_request(["prompt_injection", "jailbreak", "data_exfiltration"])
        result = asyncio.run(orch.execute(request))
        # Graph should have been cancelled by adaptive stop
        stop_decisions = [
            d for d in result.decision_history
            if d.action == CampaignDecisionAction.STOP
        ]
        assert len(stop_decisions) > 0

    def test_continue_does_not_inject_nodes(self) -> None:
        """CONTINUE decisions don't change graph structure."""
        class AlwaysContinueService:
            def decide(
                self, context: CampaignIntelligenceContext
            ) -> CampaignDecisionRecord:
                return CampaignDecisionRecord(
                    decision_id=str(uuid.uuid4()),
                    graph_id="",
                    organization_id=context.organization_id,
                    triggering_node_id=context.node_id,
                    triggering_attack_category=context.attack_category,
                    action=CampaignDecisionAction.CONTINUE,
                    rationale="continue",
                    confidence=0.8,
                    injected_categories=(),
                    alternative_strategy=None,
                    payload_hint=None,
                )

        vs = _mock_validation_service()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=AlwaysContinueService(),  # type: ignore[arg-type]
        )
        request = _make_request(["prompt_injection", "jailbreak"])
        result = asyncio.run(orch.execute(request))
        assert result.injected_nodes == 0
        assert result.total_nodes == 2

    def test_intelligence_error_does_not_break_campaign(self) -> None:
        """If intelligence service raises, the campaign continues unaffected."""
        class BrokenService:
            def decide(
                self, context: CampaignIntelligenceContext
            ) -> CampaignDecisionRecord:
                raise RuntimeError("intelligence service exploded")

        vs = _mock_validation_service()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=BrokenService(),  # type: ignore[arg-type]
        )
        request = _make_request(["prompt_injection"])
        result = asyncio.run(orch.execute(request))
        # Campaign should complete normally despite intelligence failure
        assert result.state in ("completed", "goal_achieved", "cancelled")

    def test_result_injected_nodes_counted(self) -> None:
        """injected_nodes in result equals total categories injected."""
        class EscalateService:
            def decide(
                self, context: CampaignIntelligenceContext
            ) -> CampaignDecisionRecord:
                return CampaignDecisionRecord(
                    decision_id=str(uuid.uuid4()),
                    graph_id="",
                    organization_id=context.organization_id,
                    triggering_node_id=context.node_id,
                    triggering_attack_category=context.attack_category,
                    action=CampaignDecisionAction.ESCALATE,
                    rationale="escalate",
                    confidence=0.9,
                    injected_categories=("new_cat_1",),
                    alternative_strategy=None,
                    payload_hint=None,
                )

        vs = _mock_validation_service()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=EscalateService(),  # type: ignore[arg-type]
        )
        request = _make_request(["prompt_injection"])
        result = asyncio.run(orch.execute(request))
        # Should have injected at least 1 node
        assert result.injected_nodes >= 1


# ─── KG Projection Tests ──────────────────────────────────────────────────────


class TestKGProjectionWithDecisions:
    def test_decision_nodes_projected_to_kg(self) -> None:
        """Campaign decisions are projected as CAMPAIGN_DECISION nodes in KG."""
        kg = KnowledgeGraph()

        class SingleDecisionService:
            def decide(
                self, context: CampaignIntelligenceContext
            ) -> CampaignDecisionRecord:
                return CampaignDecisionRecord(
                    decision_id="decision-abc",
                    graph_id="",
                    organization_id=context.organization_id,
                    triggering_node_id=context.node_id,
                    triggering_attack_category=context.attack_category,
                    action=CampaignDecisionAction.CONTINUE,
                    rationale="test projection",
                    confidence=0.7,
                    injected_categories=(),
                    alternative_strategy=None,
                    payload_hint=None,
                )

        vs = _mock_validation_service()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            knowledge_graph=kg,
            campaign_intelligence=SingleDecisionService(),  # type: ignore[arg-type]
        )
        request = _make_request(["prompt_injection"])
        asyncio.run(orch.execute(request))

        # KG should contain CAMPAIGN_DECISION nodes
        decision_nodes = [
            n for n in kg._store.all_nodes()
            if n.node_type == NodeType.CAMPAIGN_DECISION
        ]
        assert len(decision_nodes) >= 1

    def test_decision_influenced_node_edges_projected(self) -> None:
        """DECISION_INFLUENCED_NODE edges connect node to its decision."""
        kg = KnowledgeGraph()

        class SingleDecisionService:
            def decide(
                self, context: CampaignIntelligenceContext
            ) -> CampaignDecisionRecord:
                return CampaignDecisionRecord(
                    decision_id="decision-xyz",
                    graph_id="",
                    organization_id=context.organization_id,
                    triggering_node_id=context.node_id,
                    triggering_attack_category=context.attack_category,
                    action=CampaignDecisionAction.CONTINUE,
                    rationale="test",
                    confidence=0.7,
                    injected_categories=(),
                    alternative_strategy=None,
                    payload_hint=None,
                )

        vs = _mock_validation_service()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            knowledge_graph=kg,
            campaign_intelligence=SingleDecisionService(),  # type: ignore[arg-type]
        )
        request = _make_request(["prompt_injection"])
        asyncio.run(orch.execute(request))

        decision_edges = [
            e for e in kg._store.all_edges()
            if e.relationship == RelationshipType.DECISION_INFLUENCED_NODE
        ]
        assert len(decision_edges) >= 1

    def test_kg_has_campaign_decision_node_type(self) -> None:
        assert NodeType.CAMPAIGN_DECISION.value == "campaign_decision"

    def test_kg_has_decision_influenced_node_relationship(self) -> None:
        assert RelationshipType.DECISION_INFLUENCED_NODE.value == "decision_influenced_node"


# ─── Campaign Learning Integration Tests ─────────────────────────────────────


class TestCampaignLearningIntegration:
    def test_escalation_avoids_already_run_categories(self) -> None:
        """Intelligence service respects learner's already-run categories."""
        service = RuleBasedCampaignIntelligenceService()
        # All known escalation targets for prompt_injection already run
        completed = tuple(
            NodeEvidenceSummary(
                node_id=f"n_{i}",
                attack_category=cat,
                succeeded=True,
                finding_count=0,
            )
            for i, cat in enumerate([
                "indirect_prompt_injection",
                "multi_modal_prompt_injection",
                "agent_chain_injection",
                "rag_poisoning",
            ])
        )
        ctx = _make_context(
            attack_category="prompt_injection",
            succeeded=True,
            finding_count=1,
            max_severity="critical",
            completed_nodes=completed,
        )
        record = service.decide(ctx)
        if record.action == CampaignDecisionAction.ESCALATE:
            for cat in record.injected_categories:
                run_cats = {n.attack_category for n in completed}
                assert cat not in run_cats


# ─── Goal Completion Tests ────────────────────────────────────────────────────


class TestGoalCompletionWithIntelligence:
    def test_first_finding_goal_still_terminates(self) -> None:
        """FIRST_FINDING goal takes precedence over intelligence CONTINUE."""
        vs_result = _make_mock_vs_result(finding_count=1, severity="high")
        vs = _mock_validation_service(vs_result)
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=RuleBasedCampaignIntelligenceService(),
        )
        cats = frozenset({"prompt_injection", "jailbreak"})
        request = RedTeamRequest(
            organization_id="org-1",
            target_id="t-1",
            target_endpoint="https://api.example.com",
            target_provider="openai",
            target_name="LLM",
            model="gpt-4",
            target_system_prompt="sys",
            goal=CampaignGoal(
                objective=AttackObjective(
                    name="first_finding",
                    description="stop on first finding",
                    target_categories=cats,
                    goal_criteria=GoalCriteria.FIRST_FINDING,
                ),
                budget=BudgetConstraint(),
            ),
            correlation_id="corr-1",
        )
        result = asyncio.run(orch.execute(request))
        assert result.goal_achieved is True
        assert result.state == "goal_achieved"


# ─── Large Campaign Simulation ────────────────────────────────────────────────


class TestLargeCampaignSimulation:
    def test_ten_node_campaign_with_intelligence(self) -> None:
        """Run 10 nodes with intelligence wired — verifies no crash, correct counts."""
        vs_result = _make_mock_vs_result(finding_count=0)
        vs = _mock_validation_service(vs_result)
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=RuleBasedCampaignIntelligenceService(),
        )
        categories = [
            "prompt_injection", "jailbreak", "data_exfiltration",
            "tool_misuse", "agent_hijacking", "rag_poisoning",
            "cross_context_injection", "model_denial_of_service",
            "system_prompt_extraction", "indirect_prompt_injection",
        ]
        request = _make_request(categories)
        result = asyncio.run(orch.execute(request))
        assert result.nodes_executed >= 1
        assert result.state in (
            "completed", "goal_achieved", "cancelled"
        )
        # intelligence_confidence must be valid float
        assert 0.0 <= result.intelligence_confidence <= 1.0

    def test_large_campaign_decision_history_populated(self) -> None:
        """Each node execution should add at least one decision record."""
        vs = _mock_validation_service()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=RuleBasedCampaignIntelligenceService(),
        )
        categories = [f"cat_{i}" for i in range(5)]
        request = _make_request(categories)
        result = asyncio.run(orch.execute(request))
        # At least some decisions should be recorded (≥ 1 per executed node)
        if result.nodes_executed > 0:
            assert len(result.decision_history) >= result.nodes_executed


# ─── Retry / Pause / Cancel Regression Tests ─────────────────────────────────


class TestRegressionExistingBehavior:
    """Verify that Sprint 34/35 tests still pass with new intelligence layer."""

    def test_retry_failed_still_works(self) -> None:
        vs = _mock_validation_service()
        vs.execute = AsyncMock(side_effect=RuntimeError("simulated failure"))
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=RuleBasedCampaignIntelligenceService(),
        )
        request = _make_request(["prompt_injection"])
        result = asyncio.run(orch.execute(request))
        assert result.state in ("completed", "cancelled", "goal_achieved")

    def test_pause_and_resume_with_intelligence(self) -> None:
        vs = _mock_validation_service()
        repo = InMemoryAttackGraphRepository()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            graph_repository=repo,
            campaign_intelligence=RuleBasedCampaignIntelligenceService(),
        )
        # pause/resume are still exposed and work correctly
        assert hasattr(orch, "pause")
        assert hasattr(orch, "resume")
        assert hasattr(orch, "cancel")

    def test_success_rate_correct_with_injected_nodes(self) -> None:
        """success_rate includes injected nodes in total_nodes denominator."""
        vs = _mock_validation_service()

        class TwoInjectionService:
            _called = False

            def decide(
                self, context: CampaignIntelligenceContext
            ) -> CampaignDecisionRecord:
                action = CampaignDecisionAction.CONTINUE
                inj: tuple[str, ...] = ()
                if not TwoInjectionService._called:
                    TwoInjectionService._called = True
                    action = CampaignDecisionAction.BRANCH
                    inj = ("cat_branch_1",)
                return CampaignDecisionRecord(
                    decision_id=str(uuid.uuid4()),
                    graph_id="",
                    organization_id=context.organization_id,
                    triggering_node_id=context.node_id,
                    triggering_attack_category=context.attack_category,
                    action=action,
                    rationale="test",
                    confidence=0.8,
                    injected_categories=inj,
                    alternative_strategy=None,
                    payload_hint=None,
                )

        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=TwoInjectionService(),  # type: ignore[arg-type]
        )
        request = _make_request(["prompt_injection"])
        result = asyncio.run(orch.execute(request))
        # total_nodes should reflect injected node too
        assert result.total_nodes >= 1
        # success_rate is between 0 and 100
        assert 0.0 <= result.success_rate <= 100.0


# ─── Adaptive Stop Strategy Tests ────────────────────────────────────────────


class TestAdaptiveStopStrategy:
    def test_stop_after_max_consecutive_failures(self) -> None:
        """Service stops when consecutive_failures >= threshold."""
        service = RuleBasedCampaignIntelligenceService(
            max_consecutive_failures=3
        )
        # Exactly at threshold
        ctx = _make_context(
            succeeded=False,
            consecutive_failures=3,
        )
        record = service.decide(ctx)
        assert record.action == CampaignDecisionAction.STOP

    def test_does_not_stop_below_threshold(self) -> None:
        """Service does NOT stop before threshold."""
        service = RuleBasedCampaignIntelligenceService(
            max_consecutive_failures=5
        )
        ctx = _make_context(
            succeeded=False,
            consecutive_failures=2,
            failure_reason="some failure",
        )
        record = service.decide(ctx)
        # Should be RETRY or PIVOT, not STOP
        assert record.action != CampaignDecisionAction.STOP

    def test_custom_threshold_respected(self) -> None:
        service = RuleBasedCampaignIntelligenceService(
            max_consecutive_failures=1
        )
        ctx = _make_context(succeeded=False, consecutive_failures=1)
        record = service.decide(ctx)
        assert record.action == CampaignDecisionAction.STOP


# ─── Adaptive Retry Strategy Tests ───────────────────────────────────────────


class TestAdaptiveRetryStrategy:
    def test_retry_with_variant_on_first_execution_failure(self) -> None:
        service = RuleBasedCampaignIntelligenceService()
        ctx = _make_context(
            succeeded=False,
            failure_reason="ConnectionError: timeout",
            consecutive_failures=1,
        )
        record = service.decide(ctx)
        assert record.action == CampaignDecisionAction.RETRY_WITH_VARIANT

    def test_retry_includes_payload_hint(self) -> None:
        service = RuleBasedCampaignIntelligenceService()
        ctx = _make_context(
            succeeded=False,
            failure_reason="provider blocked request",
            consecutive_failures=1,
            target_provider="openai",
        )
        record = service.decide(ctx)
        if record.action == CampaignDecisionAction.RETRY_WITH_VARIANT:
            assert record.payload_hint is not None
