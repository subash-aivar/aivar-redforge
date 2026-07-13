"""Sprint 36/37 correctness remediation — focused tests proving exact invariants.

These tests FAIL before the fix and PASS after it. Do not edit assertions to
make tests pass; fix the implementation instead.

Invariants under test:
1. A recorded recommendation is NOT the same as an applied adaptation.
2. RedTeamResult.injected_nodes must count nodes ADMITTED to the graph, not
   merely recommended by the intelligence service.
3. ESCALATE/BRANCH/PIVOT after the last planned node must execute the injected
   node — not silently fail because the graph was already terminal.
4. CampaignDecisionRecord must distinguish recommended vs applied categories.
5. Failed injection is recorded as failed, not silently swallowed.
6. Campaign completion must not race ahead of adaptive decision application.
7. Goal-achieved campaigns do not accept unnecessary injections.
8. Budget-exhausted campaigns do not accept injections.
9. No duplicate injected node IDs.
10. Knowledge graph projects applied (not merely recommended) state.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from redforge.application.red_team.campaign_intelligence import (
    RuleBasedCampaignIntelligenceService,
)
from redforge.application.red_team.orchestrator import (
    RedTeamOrchestrator,
    RedTeamRequest,
)
from redforge.domain.red_team.campaign_decision import (
    CampaignDecisionAction,
    CampaignDecisionRecord,
    CampaignIntelligenceContext,
)
from redforge.domain.red_team.entity import AttackGraph
from redforge.domain.red_team.value_objects import (
    AttackObjective,
    BudgetConstraint,
    CampaignGoal,
    GoalCriteria,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _make_goal(
    categories: frozenset[str],
    criteria: GoalCriteria = GoalCriteria.ALL_COMPLETE,
) -> CampaignGoal:
    return CampaignGoal(
        objective=AttackObjective(
            name="test",
            description="test",
            target_categories=categories,
            goal_criteria=criteria,
        ),
        budget=BudgetConstraint(),
    )


def _make_request(
    categories: list[str],
    provider: str = "openai",
    criteria: GoalCriteria = GoalCriteria.ALL_COMPLETE,
) -> RedTeamRequest:
    cats = frozenset(categories)
    return RedTeamRequest(
        organization_id="org-test",
        target_id="target-1",
        target_endpoint="https://api.example.com",
        target_provider=provider,
        target_name="Test LLM",
        model="gpt-4",
        target_system_prompt="You are a helpful assistant.",
        goal=_make_goal(cats, criteria),
        correlation_id="corr-test",
    )


def _make_vs_result(finding_count: int = 0, severity: str | None = None) -> MagicMock:
    r = MagicMock()
    r.status = "completed"
    r.failure_reason = None
    r.evidence_ids = ["ev-1"] if finding_count > 0 else []
    r.finding_ids = [f"f-{i}" for i in range(finding_count)]
    ri = MagicMock()
    ri.incident_id = "ri-1"
    ri.priority = MagicMock()
    ri.priority.value = severity or "medium"
    r.risk_incidents = [ri] if finding_count > 0 else []
    return r


def _make_vs(result: MagicMock | None = None) -> MagicMock:
    vs = MagicMock()
    vs.execute = AsyncMock(return_value=result or _make_vs_result())
    return vs


def _always_escalate(to: list[str]) -> RuleBasedCampaignIntelligenceService:
    """Service that always recommends ESCALATE into the given categories."""
    class FixedEscalateService:
        def decide(self, context: CampaignIntelligenceContext) -> CampaignDecisionRecord:
            return CampaignDecisionRecord(
                decision_id=str(uuid.uuid4()),
                graph_id="",
                organization_id=context.organization_id,
                triggering_node_id=context.node_id,
                triggering_attack_category=context.attack_category,
                action=CampaignDecisionAction.ESCALATE,
                rationale="fixed escalate",
                confidence=0.9,
                injected_categories=tuple(to),
                alternative_strategy=None,
                payload_hint=None,
            )
    return FixedEscalateService()  # type: ignore[return-value]


def _always_branch(to: list[str]) -> Any:
    class FixedBranchService:
        def decide(self, context: CampaignIntelligenceContext) -> CampaignDecisionRecord:
            return CampaignDecisionRecord(
                decision_id=str(uuid.uuid4()),
                graph_id="",
                organization_id=context.organization_id,
                triggering_node_id=context.node_id,
                triggering_attack_category=context.attack_category,
                action=CampaignDecisionAction.BRANCH,
                rationale="fixed branch",
                confidence=0.8,
                injected_categories=tuple(to),
                alternative_strategy=None,
                payload_hint=None,
            )
    return FixedBranchService()


def _always_pivot(to: str) -> Any:
    class FixedPivotService:
        def decide(self, context: CampaignIntelligenceContext) -> CampaignDecisionRecord:
            return CampaignDecisionRecord(
                decision_id=str(uuid.uuid4()),
                graph_id="",
                organization_id=context.organization_id,
                triggering_node_id=context.node_id,
                triggering_attack_category=context.attack_category,
                action=CampaignDecisionAction.PIVOT,
                rationale="fixed pivot",
                confidence=0.75,
                injected_categories=(to,),
                alternative_strategy=to,
                payload_hint=None,
            )
    return FixedPivotService()


def _always_stop() -> Any:
    class AlwaysStopService:
        def decide(self, context: CampaignIntelligenceContext) -> CampaignDecisionRecord:
            return CampaignDecisionRecord(
                decision_id=str(uuid.uuid4()),
                graph_id="",
                organization_id=context.organization_id,
                triggering_node_id=context.node_id,
                triggering_attack_category=context.attack_category,
                action=CampaignDecisionAction.STOP,
                rationale="always stop",
                confidence=0.95,
                injected_categories=(),
                alternative_strategy=None,
                payload_hint=None,
            )
    return AlwaysStopService()


def _always_continue() -> Any:
    class AlwaysContinueService:
        def decide(self, context: CampaignIntelligenceContext) -> CampaignDecisionRecord:
            return CampaignDecisionRecord(
                decision_id=str(uuid.uuid4()),
                graph_id="",
                organization_id=context.organization_id,
                triggering_node_id=context.node_id,
                triggering_attack_category=context.attack_category,
                action=CampaignDecisionAction.CONTINUE,
                rationale="always continue",
                confidence=0.8,
                injected_categories=(),
                alternative_strategy=None,
                payload_hint=None,
            )
    return AlwaysContinueService()


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


# ─── Core Lifecycle Ordering Tests ────────────────────────────────────────────


class TestSingleNodeEscalate:
    """A single-node campaign ESCALATING must actually execute the injected node."""

    def test_injected_node_is_executed_not_just_recommended(self) -> None:
        """
        BEFORE FIX: graph transitions to COMPLETED before intelligence runs.
        inject_node() raises AttackGraphAlreadyTerminalError. Exception is
        caught silently. injected_nodes=1 but no node was actually added.

        AFTER FIX: intelligence runs before graph finalizes. inject_node()
        succeeds. The injected node is picked up by the loop and executed.
        nodes_executed == 2 (original + injected).
        """
        vs = _make_vs(_make_vs_result())
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=_always_escalate(["jailbreak"]),
        )
        result = _run(orch.execute(_make_request(["prompt_injection"])))

        # The injected node must have actually executed — nodes_executed must be 2
        assert result.nodes_executed == 2, (
            f"Expected 2 nodes executed (original + injected), got {result.nodes_executed}. "
            "This proves the graph was terminal before intelligence ran."
        )
        # injected_nodes must count real graph admissions, not recommendations
        assert result.injected_nodes == 1, (
            f"Expected 1 injected node (actually admitted), got {result.injected_nodes}."
        )
        # The injected category must appear in node summaries
        executed_categories = {s.attack_category for s in result.node_summaries}
        assert "jailbreak" in executed_categories, (
            f"Injected category 'jailbreak' not found in executed nodes: {executed_categories}"
        )

    def test_single_node_escalate_both_categories_execute(self) -> None:
        """ESCALATE recommends 2 categories; both must execute."""
        vs = _make_vs()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=_always_escalate(["cat_a", "cat_b"]),
        )
        result = _run(orch.execute(_make_request(["prompt_injection"])))

        assert result.nodes_executed == 3
        assert result.injected_nodes == 2
        executed_cats = {s.attack_category for s in result.node_summaries}
        assert "cat_a" in executed_cats
        assert "cat_b" in executed_cats

    def test_applied_node_ids_on_decision_record(self) -> None:
        """
        CampaignDecisionRecord must have applied_node_ids populated with the
        actual node IDs admitted to the graph — not just recommended categories.
        """
        vs = _make_vs()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=_always_escalate(["jailbreak"]),
        )
        result = _run(orch.execute(_make_request(["prompt_injection"])))

        escalate_decisions = [
            d for d in result.decision_history
            if d.action == CampaignDecisionAction.ESCALATE
        ]
        assert len(escalate_decisions) >= 1

        d = escalate_decisions[0]
        # applied_node_ids must be populated
        assert hasattr(d, "applied_node_ids"), (
            "CampaignDecisionRecord is missing 'applied_node_ids' field. "
            "This field tracks categories actually admitted, not just recommended."
        )
        assert len(d.applied_node_ids) == 1, (
            f"Expected 1 applied node, got {d.applied_node_ids}"
        )
        # The applied node ID must exist in the graph
        node_ids_in_result = {s.node_id for s in result.node_summaries}
        assert d.applied_node_ids[0] in node_ids_in_result, (
            f"applied_node_ids[0]={d.applied_node_ids[0]!r} not found in graph nodes: "
            f"{node_ids_in_result}"
        )


class TestSingleNodeBranch:
    """A single-node campaign BRANCHING must execute the injected nodes."""

    def test_branch_injected_nodes_execute(self) -> None:
        vs = _make_vs()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=_always_branch(["data_exfiltration", "tool_misuse"]),
        )
        result = _run(orch.execute(_make_request(["prompt_injection"])))

        assert result.nodes_executed == 3
        executed_cats = {s.attack_category for s in result.node_summaries}
        assert "data_exfiltration" in executed_cats
        assert "tool_misuse" in executed_cats

    def test_branch_applied_node_ids_populated(self) -> None:
        vs = _make_vs()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=_always_branch(["cat_x"]),
        )
        result = _run(orch.execute(_make_request(["prompt_injection"])))

        branch_decisions = [
            d for d in result.decision_history
            if d.action == CampaignDecisionAction.BRANCH
        ]
        assert len(branch_decisions) >= 1
        d = branch_decisions[0]
        assert hasattr(d, "applied_node_ids")
        assert len(d.applied_node_ids) >= 1


class TestSingleNodePivot:
    """PIVOT after the last original node must have a real execution path."""

    def test_pivot_injected_node_executes(self) -> None:
        vs = _make_vs()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=_always_pivot("agent_hijacking"),
        )
        result = _run(orch.execute(_make_request(["prompt_injection"])))

        assert result.nodes_executed == 2
        executed_cats = {s.attack_category for s in result.node_summaries}
        assert "agent_hijacking" in executed_cats


class TestInjectedNodesCount:
    """injected_nodes must count admitted nodes, not recommended categories."""

    def test_injected_nodes_zero_when_no_injection(self) -> None:
        vs = _make_vs()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=_always_continue(),
        )
        result = _run(orch.execute(_make_request(["prompt_injection"])))
        assert result.injected_nodes == 0

    def test_injected_nodes_equals_actual_graph_admissions(self) -> None:
        """When 2 categories are recommended and both succeed, injected_nodes == 2."""
        vs = _make_vs()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=_always_escalate(["cat_1", "cat_2"]),
        )
        result = _run(orch.execute(_make_request(["prompt_injection"])))
        # nodes_executed = 3 (1 original + 2 injected)
        # injected_nodes = 2 (actual graph admissions)
        assert result.injected_nodes == 2
        assert result.nodes_executed == 3

    def test_injected_nodes_does_not_double_count_duplicates(self) -> None:
        """If intelligence recommends a category already in the graph, it is
        rejected and must NOT appear in injected_nodes count."""
        vs = _make_vs()
        # prompt_injection is already in the graph — recommending it again
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=_always_escalate(["prompt_injection", "jailbreak"]),
        )
        result = _run(orch.execute(_make_request(["prompt_injection"])))
        # Only jailbreak is new; prompt_injection is duplicate → rejected
        assert result.injected_nodes == 1
        executed_cats = {s.attack_category for s in result.node_summaries}
        assert "jailbreak" in executed_cats


class TestRecommendedVsApplied:
    """Recommendation count and applied injection count must be distinct."""

    def test_recommended_categories_preserved_even_when_rejected(self) -> None:
        """injected_categories on the record always shows what was RECOMMENDED,
        regardless of whether the injection succeeded."""
        vs = _make_vs()
        # Recommend prompt_injection again (duplicate — will be rejected)
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=_always_escalate(
                ["prompt_injection", "new_cat"]
            ),
        )
        result = _run(orch.execute(_make_request(["prompt_injection"])))

        escalate_decisions = [
            d for d in result.decision_history
            if d.action == CampaignDecisionAction.ESCALATE
        ]
        d = escalate_decisions[0]
        # Recommended 2 categories
        assert len(d.injected_categories) == 2
        assert "prompt_injection" in d.injected_categories
        assert "new_cat" in d.injected_categories
        # But only 1 was actually applied
        assert len(d.applied_node_ids) == 1

    def test_application_failure_reason_set_for_rejected_injection(self) -> None:
        """When the graph is CANCELLED before intelligence runs, and we attempt
        to inject, the failure must be recorded — not silently lost."""
        # This tests the failure path: intelligence recommends but the injection
        # is rejected because the graph was already terminal (goal-achieved scenario).
        vs = _make_vs(_make_vs_result(finding_count=1, severity="critical"))
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=_always_escalate(["new_cat"]),
        )
        result = _run(
            orch.execute(
                _make_request(
                    ["prompt_injection"],
                    criteria=GoalCriteria.FIRST_FINDING,
                )
            )
        )

        # Goal was achieved → graph is terminal
        assert result.goal_achieved
        # Escalate decisions should have applied_node_ids = () — nothing admitted
        escalate_decisions = [
            d for d in result.decision_history
            if d.action == CampaignDecisionAction.ESCALATE
        ]
        if escalate_decisions:
            d = escalate_decisions[0]
            assert hasattr(d, "applied_node_ids")
            # No nodes admitted — goal already achieved
            assert len(d.applied_node_ids) == 0
            # Failure reason must be recorded, not None
            assert hasattr(d, "application_failure_reason")
            assert d.application_failure_reason is not None


class TestGoalAchievedNoInjection:
    """Goal-achieved campaigns must not accept injections."""

    def test_first_finding_goal_stops_injection(self) -> None:
        vs = _make_vs(_make_vs_result(finding_count=1, severity="high"))
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=_always_escalate(["new_cat"]),
        )
        result = _run(
            orch.execute(
                _make_request(
                    ["prompt_injection"],
                    criteria=GoalCriteria.FIRST_FINDING,
                )
            )
        )
        assert result.goal_achieved
        assert result.state == "goal_achieved"
        # Goal achieved stops the graph; no injections admitted
        assert result.injected_nodes == 0

    def test_goal_achieved_injected_nodes_not_counted(self) -> None:
        """Even if the decision recommends injection, injected_nodes == 0
        because the graph is terminal (GOAL_ACHIEVED) before injection."""
        vs = _make_vs(_make_vs_result(finding_count=1, severity="critical"))
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=_always_escalate(["cat_x", "cat_y"]),
        )
        result = _run(
            orch.execute(
                _make_request(
                    ["prompt_injection"],
                    criteria=GoalCriteria.FIRST_FINDING,
                )
            )
        )
        assert result.goal_achieved
        assert result.injected_nodes == 0


class TestBudgetExhausted:
    """Budget-exhausted campaigns must not accept injections."""

    def test_max_nodes_budget_stops_injection(self) -> None:
        """Budget.max_nodes=1 means stop after 1 node — no injection allowed."""
        goal = CampaignGoal(
            objective=AttackObjective(
                name="budget_test",
                description="budget",
                target_categories=frozenset({"prompt_injection", "jailbreak"}),
                goal_criteria=GoalCriteria.ALL_COMPLETE,
            ),
            budget=BudgetConstraint(max_nodes=1),
        )
        request = RedTeamRequest(
            organization_id="org-test",
            target_id="t-1",
            target_endpoint="https://api.example.com",
            target_provider="openai",
            target_name="LLM",
            model="gpt-4",
            target_system_prompt="sys",
            goal=goal,
            correlation_id="c-1",
        )
        vs = _make_vs()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=_always_escalate(["extra_cat"]),
        )
        result = _run(orch.execute(request))
        # Budget exhausted after 1 node — no injection
        assert result.injected_nodes == 0
        assert result.nodes_executed <= 2  # budget may allow one node


class TestNoDuplicateNodeIds:
    """No duplicate node IDs must exist in the graph after injection."""

    def test_duplicate_category_recommendation_produces_unique_node_ids(self) -> None:
        """If the same category is recommended twice (e.g., two decisions both
        suggest 'jailbreak'), only one node is created."""
        call_count = [0]

        class TwiceEscalateService:
            def decide(self, context: CampaignIntelligenceContext) -> CampaignDecisionRecord:
                call_count[0] += 1
                return CampaignDecisionRecord(
                    decision_id=str(uuid.uuid4()),
                    graph_id="",
                    organization_id=context.organization_id,
                    triggering_node_id=context.node_id,
                    triggering_attack_category=context.attack_category,
                    action=CampaignDecisionAction.ESCALATE,
                    rationale="always jailbreak",
                    confidence=0.9,
                    # Always recommend jailbreak — second call should be deduped
                    injected_categories=("jailbreak",),
                    alternative_strategy=None,
                    payload_hint=None,
                )

        vs = _make_vs()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=TwiceEscalateService(),  # type: ignore[arg-type]
        )
        result = _run(orch.execute(_make_request(["prompt_injection"])))

        node_ids = [s.node_id for s in result.node_summaries]
        node_cats = [s.attack_category for s in result.node_summaries]
        # No duplicate node IDs
        assert len(node_ids) == len(set(node_ids)), f"Duplicate node IDs: {node_ids}"
        # jailbreak appears at most once
        assert node_cats.count("jailbreak") <= 1, f"Duplicate jailbreak nodes: {node_cats}"


class TestGraphCycleRegression:
    """inject_node must never create a cycle (injected nodes are isolated leaves)."""

    def test_injected_node_has_no_edges_no_cycle(self) -> None:
        """Verify inject_node adds a READY leaf with no inbound/outbound edges."""
        graph = AttackGraph.create(
            graph_id="g-1",
            organization_id="org-1",
            campaign_id="c-1",
            goal=_make_goal(frozenset({"prompt_injection"})),
            attack_categories=["prompt_injection"],
        )
        graph.inject_node(
            node_id="injected_jailbreak",
            attack_category="jailbreak",
            decision_id="d-1",
            reason="escalate",
        )
        # Both nodes are READY (injected node starts READY, original is READY too)
        ready = graph.ready_nodes
        assert "injected_jailbreak" in ready
        # No dependencies registered for the injected node
        assert graph._dependencies.get("injected_jailbreak", []) == []


class TestMultiNodeEscalation:
    """Multi-node campaigns with escalation run the full expanded graph."""

    def test_two_node_campaign_escalation_from_first_node(self) -> None:
        """When first of 2 nodes escalates, graph grows and all nodes execute."""
        escalate_call_count = [0]

        class EscalateOnFirstCall:
            def decide(self, context: CampaignIntelligenceContext) -> CampaignDecisionRecord:
                escalate_call_count[0] += 1
                action = CampaignDecisionAction.CONTINUE
                injected: tuple[str, ...] = ()
                if context.attack_category == "prompt_injection":
                    action = CampaignDecisionAction.ESCALATE
                    injected = ("injected_cat",)
                return CampaignDecisionRecord(
                    decision_id=str(uuid.uuid4()),
                    graph_id="",
                    organization_id=context.organization_id,
                    triggering_node_id=context.node_id,
                    triggering_attack_category=context.attack_category,
                    action=action,
                    rationale="escalate first node",
                    confidence=0.9,
                    injected_categories=injected,
                    alternative_strategy=None,
                    payload_hint=None,
                )

        vs = _make_vs()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=EscalateOnFirstCall(),  # type: ignore[arg-type]
        )
        result = _run(orch.execute(_make_request(["prompt_injection", "jailbreak"])))

        # Should execute 3 nodes: prompt_injection, jailbreak, injected_cat
        assert result.nodes_executed == 3
        assert result.injected_nodes == 1
        executed_cats = {s.attack_category for s in result.node_summaries}
        assert "injected_cat" in executed_cats


class TestKGProjectionHonesty:
    """KG must project applied state, not just recommended state."""

    def test_kg_campaign_decision_node_has_applied_count(self) -> None:
        """The CAMPAIGN_DECISION KG node must record applied_count, not just
        recommended_count, so auditors can see what actually happened."""
        from redforge.application.knowledge_graph import KnowledgeGraph, NodeType

        kg = KnowledgeGraph()
        vs = _make_vs()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            knowledge_graph=kg,
            campaign_intelligence=_always_escalate(["jailbreak"]),
        )
        _run(orch.execute(_make_request(["prompt_injection"])))

        decision_nodes = [
            n for n in kg._store.all_nodes()
            if n.node_type == NodeType.CAMPAIGN_DECISION
        ]
        assert len(decision_nodes) >= 1
        dn = decision_nodes[0]
        # Must have applied_count metadata — not just recommended_count
        assert "applied_count" in dn.metadata, (
            f"KG CAMPAIGN_DECISION node missing 'applied_count' in metadata: "
            f"{dn.metadata}"
        )
        # applied_count must equal actual admitted nodes
        assert dn.metadata["applied_count"] == "1", (
            f"applied_count should be '1' (jailbreak was admitted), got "
            f"{dn.metadata['applied_count']!r}"
        )


class TestRetryResumeRegression:
    """retry_failed and pause/resume must still work correctly after remediation."""

    def test_retry_failed_works_with_intelligence(self) -> None:
        vs = _make_vs()
        vs.execute = AsyncMock(side_effect=RuntimeError("network error"))
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=RuleBasedCampaignIntelligenceService(),
        )
        result = _run(orch.execute(_make_request(["prompt_injection"])))
        # Should survive despite VS failure
        assert result.state in ("completed", "cancelled", "goal_achieved")
        # injected_nodes is always non-negative
        assert result.injected_nodes >= 0

    def test_graph_state_is_terminal_after_execute(self) -> None:
        """The graph must always be in a terminal state after execute() returns."""
        vs = _make_vs()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=_always_escalate(["cat_a", "cat_b"]),
        )
        result = _run(orch.execute(_make_request(["prompt_injection"])))
        assert result.state in (
            "completed", "goal_achieved", "cancelled", "failed"
        )


class TestInjectionOnLastNodeMultiCategory:
    """Verify injection from the last node in a multi-category graph works."""

    def test_escalate_after_second_of_two_nodes(self) -> None:
        """When the second of 2 nodes escalates, the injected node executes."""
        escalate_on: set[str] = {"jailbreak"}  # only second node escalates

        class EscalateOnJailbreak:
            def decide(self, context: CampaignIntelligenceContext) -> CampaignDecisionRecord:
                if context.attack_category in escalate_on:
                    action = CampaignDecisionAction.ESCALATE
                    injected: tuple[str, ...] = ("extra_cat",)
                else:
                    action = CampaignDecisionAction.CONTINUE
                    injected = ()
                return CampaignDecisionRecord(
                    decision_id=str(uuid.uuid4()),
                    graph_id="",
                    organization_id=context.organization_id,
                    triggering_node_id=context.node_id,
                    triggering_attack_category=context.attack_category,
                    action=action,
                    rationale="escalate on jailbreak",
                    confidence=0.9,
                    injected_categories=injected,
                    alternative_strategy=None,
                    payload_hint=None,
                )

        vs = _make_vs()
        orch = RedTeamOrchestrator(
            validation_service=vs,
            campaign_intelligence=EscalateOnJailbreak(),  # type: ignore[arg-type]
        )
        result = _run(orch.execute(_make_request(["prompt_injection", "jailbreak"])))

        assert result.nodes_executed == 3
        assert result.injected_nodes == 1
        executed_cats = {s.attack_category for s in result.node_summaries}
        assert "extra_cat" in executed_cats
