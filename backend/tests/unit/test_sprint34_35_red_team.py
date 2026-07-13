"""Sprint 34/35 — Goal-Oriented AI Red Team Orchestration Platform tests."""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock

import pytest

from redforge.application.red_team.orchestrator import (
    InMemoryAttackGraphRepository,
    RedTeamOrchestrator,
    RedTeamRequest,
    _max_severity_from_result,
)
from redforge.domain.red_team.entity import AttackGraph
from redforge.domain.red_team.exceptions import (
    AttackGraphCycleError,
    AttackGraphNotRunningError,
    BudgetExhaustedError,
    GoalAchievedSignal,
)
from redforge.domain.red_team.value_objects import (
    AttackEdge,
    AttackGraphState,
    AttackNodeState,
    AttackObjective,
    BudgetConstraint,
    CampaignGoal,
    EdgeCondition,
    GoalCriteria,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────

ORG = "org-test"
CAMPAIGN = "camp-001"


def _objective(
    cats: list[str],
    criteria: GoalCriteria = GoalCriteria.ALL_COMPLETE,
    *,
    severity_threshold: str = "high",
    finding_count_threshold: int = 1,
    coverage_threshold_pct: float = 80.0,
) -> AttackObjective:
    return AttackObjective(
        name="Test Objective",
        description="Test",
        target_categories=frozenset(cats),
        goal_criteria=criteria,
        severity_threshold=severity_threshold,
        finding_count_threshold=finding_count_threshold,
        coverage_threshold_pct=coverage_threshold_pct,
    )


def _goal(
    cats: list[str],
    criteria: GoalCriteria = GoalCriteria.ALL_COMPLETE,
    budget: BudgetConstraint | None = None,
    **kw: object,
) -> CampaignGoal:
    return CampaignGoal(
        objective=_objective(cats, criteria, **kw),  # type: ignore[arg-type]
        budget=budget or BudgetConstraint(),
    )


def _graph(
    cats: list[str],
    criteria: GoalCriteria = GoalCriteria.ALL_COMPLETE,
    edges: list[AttackEdge] | None = None,
    budget: BudgetConstraint | None = None,
    **kw: object,
) -> AttackGraph:
    return AttackGraph.create(
        graph_id="g-001",
        organization_id=ORG,
        campaign_id=CAMPAIGN,
        goal=_goal(cats, criteria, budget, **kw),
        attack_categories=cats,
        edges=edges,
    )


# ─── Value Object tests ────────────────────────────────────────────────────────

class TestAttackObjective:
    def test_valid_objective(self) -> None:
        obj = _objective(["prompt_injection"])
        assert obj.name == "Test Objective"
        assert "prompt_injection" in obj.target_categories

    def test_empty_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="name"):
            AttackObjective(
                name="",
                description="d",
                target_categories=frozenset(["cat"]),
                goal_criteria=GoalCriteria.ALL_COMPLETE,
            )

    def test_empty_categories_rejected(self) -> None:
        with pytest.raises(ValueError, match="target_categories"):
            AttackObjective(
                name="n",
                description="d",
                target_categories=frozenset(),
                goal_criteria=GoalCriteria.ALL_COMPLETE,
            )

    def test_invalid_coverage_threshold(self) -> None:
        with pytest.raises(ValueError, match="coverage_threshold_pct"):
            AttackObjective(
                name="n",
                description="d",
                target_categories=frozenset(["cat"]),
                goal_criteria=GoalCriteria.COVERAGE_THRESHOLD,
                coverage_threshold_pct=0.0,
            )

    def test_invalid_finding_count(self) -> None:
        with pytest.raises(ValueError, match="finding_count_threshold"):
            AttackObjective(
                name="n",
                description="d",
                target_categories=frozenset(["cat"]),
                goal_criteria=GoalCriteria.FINDING_COUNT,
                finding_count_threshold=0,
            )

    def test_self_referencing_edge_rejected(self) -> None:
        with pytest.raises(ValueError, match="self-referencing"):
            AttackEdge(from_node_id="a", to_node_id="a")


# ─── AttackGraph construction ─────────────────────────────────────────────────

class TestAttackGraphCreate:
    def test_single_node_starts_ready(self) -> None:
        g = _graph(["prompt_injection"])
        results = list(g.all_results())
        assert len(results) == 1
        assert results[0].state == AttackNodeState.READY

    def test_multiple_independent_nodes_all_ready(self) -> None:
        g = _graph(["prompt_injection", "data_exfiltration", "policy_bypass"])
        states = {r.state for r in g.all_results()}
        assert states == {AttackNodeState.READY}

    def test_dependent_node_starts_pending(self) -> None:
        g = _graph(
            ["a", "b"],
            edges=[AttackEdge(from_node_id="node_0_a", to_node_id="node_1_b")],
        )
        by_id = {r.node_id: r for r in g.all_results()}
        assert by_id["node_0_a"].state == AttackNodeState.READY
        assert by_id["node_1_b"].state == AttackNodeState.PENDING

    def test_cycle_detection(self) -> None:
        with pytest.raises(AttackGraphCycleError):
            AttackGraph.create(
                graph_id="g",
                organization_id=ORG,
                campaign_id=CAMPAIGN,
                goal=_goal(["a", "b"]),
                attack_categories=["a", "b"],
                edges=[
                    AttackEdge(from_node_id="node_0_a", to_node_id="node_1_b"),
                    AttackEdge(from_node_id="node_1_b", to_node_id="node_0_a"),
                ],
            )

    def test_empty_categories_rejected(self) -> None:
        with pytest.raises(ValueError):
            AttackGraph.create(
                graph_id="g",
                organization_id=ORG,
                campaign_id=CAMPAIGN,
                goal=_goal(["x"]),
                attack_categories=[],
            )

    def test_events_emitted_on_create(self) -> None:
        g = _graph(["prompt_injection"])
        events = g.collect_events()
        assert any(type(e).__name__ == "AttackGraphCreated" for e in events)

    def test_collect_events_clears(self) -> None:
        g = _graph(["prompt_injection"])
        g.collect_events()
        assert g.collect_events() == []


# ─── State machine transitions ────────────────────────────────────────────────

class TestAttackGraphStateTransitions:
    def test_mark_node_running(self) -> None:
        g = _graph(["prompt_injection"])
        nid = g.execution_order[0]
        g.mark_node_running(nid)
        assert g._results[nid].state == AttackNodeState.RUNNING

    def test_mark_node_completed(self) -> None:
        g = _graph(["prompt_injection"])
        nid = g.execution_order[0]
        g.mark_node_running(nid)
        g.mark_node_completed(
            nid, evidence_ids=["ev1"], finding_ids=["f1"],
            risk_incident_ids=[], duration_ms=100, max_severity_found="high",
        )
        assert g._results[nid].state == AttackNodeState.COMPLETED

    def test_mark_node_failed(self) -> None:
        g = _graph(["prompt_injection"])
        nid = g.execution_order[0]
        g.mark_node_running(nid)
        g.mark_node_failed(nid, failure_reason="timeout", duration_ms=50)
        assert g._results[nid].state == AttackNodeState.FAILED

    def test_pause_and_resume(self) -> None:
        g = _graph(["prompt_injection"])
        g.pause()
        assert g.state == AttackGraphState.PAUSED
        g.resume()
        assert g.state == AttackGraphState.RUNNING

    def test_cancel(self) -> None:
        g = _graph(["prompt_injection"])
        g.cancel("user requested")
        assert g.state == AttackGraphState.CANCELLED

    def test_resume_running_graph_raises(self) -> None:
        g = _graph(["prompt_injection"])
        with pytest.raises(AttackGraphNotRunningError):
            g.resume()  # can't resume a non-PAUSED graph

    def test_graph_completed_when_all_terminal(self) -> None:
        g = _graph(["a", "b"])
        for nid in g.execution_order:
            g.mark_node_running(nid)
            g.mark_node_completed(
                nid, evidence_ids=[], finding_ids=[],
                risk_incident_ids=[], duration_ms=10, max_severity_found=None,
            )
        # Sprint 36/37: natural completion is deferred so intelligence can inject
        # nodes before the graph finalizes. Caller must call try_complete() explicitly.
        g.try_complete()
        assert g.state == AttackGraphState.COMPLETED


# ─── Goal criteria ────────────────────────────────────────────────────────────

class TestGoalCriteria:
    def test_first_finding_triggers_signal(self) -> None:
        g = _graph(["a", "b"], GoalCriteria.FIRST_FINDING)
        nid = g.execution_order[0]
        g.mark_node_running(nid)
        with pytest.raises(GoalAchievedSignal):
            g.mark_node_completed(
                nid, evidence_ids=["ev1"], finding_ids=["f1"],
                risk_incident_ids=[], duration_ms=10, max_severity_found="low",
            )
        assert g.state == AttackGraphState.GOAL_ACHIEVED

    def test_first_finding_no_signal_without_findings(self) -> None:
        g = _graph(["a", "b"], GoalCriteria.FIRST_FINDING)
        nid = g.execution_order[0]
        g.mark_node_running(nid)
        # Should NOT raise — zero findings
        g.mark_node_completed(
            nid, evidence_ids=[], finding_ids=[],
            risk_incident_ids=[], duration_ms=10, max_severity_found=None,
        )
        assert g.state == AttackGraphState.RUNNING

    def test_severity_threshold_critical_triggers(self) -> None:
        g = _graph(["a"], GoalCriteria.SEVERITY_THRESHOLD, severity_threshold="high")
        nid = g.execution_order[0]
        g.mark_node_running(nid)
        with pytest.raises(GoalAchievedSignal):
            g.mark_node_completed(
                nid, evidence_ids=[], finding_ids=["f1"],
                risk_incident_ids=[], duration_ms=10, max_severity_found="critical",
            )

    def test_severity_threshold_low_does_not_trigger(self) -> None:
        g = _graph(["a"], GoalCriteria.SEVERITY_THRESHOLD, severity_threshold="high")
        nid = g.execution_order[0]
        g.mark_node_running(nid)
        g.mark_node_completed(
            nid, evidence_ids=[], finding_ids=["f1"],
            risk_incident_ids=[], duration_ms=10, max_severity_found="low",
        )
        g.try_complete()
        assert g.state == AttackGraphState.COMPLETED

    def test_finding_count_threshold(self) -> None:
        g = _graph(
            ["a", "b", "c"], GoalCriteria.FINDING_COUNT,
            finding_count_threshold=2,
        )
        nodes = g.execution_order
        g.mark_node_running(nodes[0])
        g.mark_node_completed(
            nodes[0], evidence_ids=[], finding_ids=["f1"],
            risk_incident_ids=[], duration_ms=10, max_severity_found=None,
        )
        # 1 finding — not yet
        assert g.state == AttackGraphState.RUNNING

        g.mark_node_running(nodes[1])
        with pytest.raises(GoalAchievedSignal):
            g.mark_node_completed(
                nodes[1], evidence_ids=[], finding_ids=["f2"],
                risk_incident_ids=[], duration_ms=10, max_severity_found=None,
            )

    def test_coverage_threshold(self) -> None:
        # 3 categories, threshold 50% → 2 completed triggers
        g = _graph(
            ["a", "b", "c"], GoalCriteria.COVERAGE_THRESHOLD,
            coverage_threshold_pct=50.0,
        )
        nodes = g.execution_order
        g.mark_node_running(nodes[0])
        g.mark_node_completed(
            nodes[0], evidence_ids=[], finding_ids=[],
            risk_incident_ids=[], duration_ms=10, max_severity_found=None,
        )
        g.mark_node_running(nodes[1])
        with pytest.raises(GoalAchievedSignal):
            g.mark_node_completed(
                nodes[1], evidence_ids=[], finding_ids=[],
                risk_incident_ids=[], duration_ms=10, max_severity_found=None,
            )

    def test_all_complete_no_early_exit(self) -> None:
        g = _graph(["a", "b", "c"], GoalCriteria.ALL_COMPLETE)
        for nid in g.execution_order:
            g.mark_node_running(nid)
            g.mark_node_completed(
                nid, evidence_ids=[], finding_ids=["f"],
                risk_incident_ids=[], duration_ms=10, max_severity_found="critical",
            )
        # No GoalAchievedSignal — all_complete never raises it.
        # try_complete() required: deferred finalization (Sprint 36/37).
        g.try_complete()
        assert g.state == AttackGraphState.COMPLETED


# ─── Budget constraints ───────────────────────────────────────────────────────

class TestBudgetConstraints:
    def test_max_nodes_budget(self) -> None:
        g = _graph(
            ["a", "b", "c"],
            budget=BudgetConstraint(max_nodes=1),
        )
        nid = g.execution_order[0]
        g.mark_node_running(nid)
        with pytest.raises(BudgetExhaustedError) as exc_info:
            g.mark_node_completed(
                nid, evidence_ids=[], finding_ids=[],
                risk_incident_ids=[], duration_ms=10, max_severity_found=None,
            )
        assert exc_info.value.limit_type == "max_nodes"

    def test_max_findings_budget(self) -> None:
        g = _graph(
            ["a", "b"],
            budget=BudgetConstraint(max_findings=1),
        )
        nid = g.execution_order[0]
        g.mark_node_running(nid)
        with pytest.raises(BudgetExhaustedError) as exc_info:
            g.mark_node_completed(
                nid, evidence_ids=[], finding_ids=["f1"],
                risk_incident_ids=[], duration_ms=10, max_severity_found=None,
            )
        assert exc_info.value.limit_type == "max_findings"


# ─── Conditional edges ────────────────────────────────────────────────────────

class TestConditionalEdges:
    def test_on_success_propagates_to_ready(self) -> None:
        g = _graph(
            ["a", "b"],
            edges=[AttackEdge("node_0_a", "node_1_b", EdgeCondition.ON_SUCCESS)],
        )
        g.mark_node_running("node_0_a")
        g.mark_node_completed(
            "node_0_a", evidence_ids=[], finding_ids=[],
            risk_incident_ids=[], duration_ms=10, max_severity_found=None,
        )
        assert g._results["node_1_b"].state == AttackNodeState.READY

    def test_on_success_blocks_on_failure(self) -> None:
        g = _graph(
            ["a", "b"],
            edges=[AttackEdge("node_0_a", "node_1_b", EdgeCondition.ON_SUCCESS)],
        )
        g.mark_node_running("node_0_a")
        g.mark_node_failed("node_0_a", failure_reason="err", duration_ms=5)
        assert g._results["node_1_b"].state == AttackNodeState.BLOCKED

    def test_on_failure_runs_on_failure(self) -> None:
        g = _graph(
            ["a", "b"],
            edges=[AttackEdge("node_0_a", "node_1_b", EdgeCondition.ON_FAILURE)],
        )
        g.mark_node_running("node_0_a")
        g.mark_node_failed("node_0_a", failure_reason="err", duration_ms=5)
        assert g._results["node_1_b"].state == AttackNodeState.READY

    def test_always_edge_runs_after_failure(self) -> None:
        g = _graph(
            ["a", "b"],
            edges=[AttackEdge("node_0_a", "node_1_b", EdgeCondition.ALWAYS)],
        )
        g.mark_node_running("node_0_a")
        g.mark_node_failed("node_0_a", failure_reason="err", duration_ms=5)
        assert g._results["node_1_b"].state == AttackNodeState.READY

    def test_always_edge_runs_after_success(self) -> None:
        g = _graph(
            ["a", "b"],
            edges=[AttackEdge("node_0_a", "node_1_b", EdgeCondition.ALWAYS)],
        )
        g.mark_node_running("node_0_a")
        g.mark_node_completed(
            "node_0_a", evidence_ids=[], finding_ids=[],
            risk_incident_ids=[], duration_ms=10, max_severity_found=None,
        )
        assert g._results["node_1_b"].state == AttackNodeState.READY


# ─── Retry / reset_failed_nodes ───────────────────────────────────────────────

class TestRetryFailedNodes:
    def test_reset_failed_independent_nodes(self) -> None:
        g = _graph(["a", "b", "c"])
        for nid in ["node_0_a", "node_1_b"]:
            g.mark_node_running(nid)
            g.mark_node_failed(nid, failure_reason="err", duration_ms=5)
        reset = g.reset_failed_nodes()
        assert "node_0_a" in reset
        assert "node_1_b" in reset
        assert g._results["node_0_a"].state == AttackNodeState.READY
        assert g._results["node_1_b"].state == AttackNodeState.READY

    def test_reset_emits_ready_events(self) -> None:
        g = _graph(["a", "b"])  # 2 nodes so graph isn't terminal after one failure
        g.mark_node_running("node_0_a")
        g.mark_node_failed("node_0_a", failure_reason="err", duration_ms=5)
        g.collect_events()  # clear
        g.reset_failed_nodes()
        events = g.collect_events()
        event_types = [type(e).__name__ for e in events]
        assert "AttackNodeReady" in event_types


# ─── Topological order ────────────────────────────────────────────────────────

class TestTopologicalOrder:
    def test_linear_chain_order(self) -> None:
        g = _graph(
            ["a", "b", "c"],
            edges=[
                AttackEdge("node_0_a", "node_1_b"),
                AttackEdge("node_1_b", "node_2_c"),
            ],
        )
        order = g.execution_order
        assert order.index("node_0_a") < order.index("node_1_b")
        assert order.index("node_1_b") < order.index("node_2_c")

    def test_diamond_dependency_order(self) -> None:
        # a → b, a → c, b → d, c → d
        g = _graph(
            ["a", "b", "c", "d"],
            edges=[
                AttackEdge("node_0_a", "node_1_b"),
                AttackEdge("node_0_a", "node_2_c"),
                AttackEdge("node_1_b", "node_3_d"),
                AttackEdge("node_2_c", "node_3_d"),
            ],
        )
        order = g.execution_order
        assert order[0] == "node_0_a"
        assert order[-1] == "node_3_d"


# ─── Evidence correlation ─────────────────────────────────────────────────────

class TestEvidenceCorrelation:
    def test_evidence_accumulated_per_node(self) -> None:
        g = _graph(["a"])
        nid = "node_0_a"
        g.mark_node_running(nid)
        g.mark_node_completed(
            nid,
            evidence_ids=["ev1", "ev2"],
            finding_ids=["f1"],
            risk_incident_ids=["ri1"],
            duration_ms=200,
            max_severity_found="critical",
        )
        r = g._results[nid]
        assert r.evidence_ids == ["ev1", "ev2"]
        assert r.finding_ids == ["f1"]
        assert r.risk_incident_ids == ["ri1"]
        assert r.max_severity_found == "critical"

    def test_all_results_includes_evidence(self) -> None:
        g = _graph(["a", "b"])
        for nid in g.execution_order:
            g.mark_node_running(nid)
            g.mark_node_completed(
                nid, evidence_ids=[f"ev-{nid}"], finding_ids=[f"f-{nid}"],
                risk_incident_ids=[], duration_ms=10, max_severity_found=None,
            )
        all_ev = [eid for r in g.all_results() for eid in r.evidence_ids]
        assert len(all_ev) == 2


# ─── InMemoryAttackGraphRepository ───────────────────────────────────────────

class TestInMemoryAttackGraphRepository:
    @pytest.mark.asyncio
    async def test_save_and_get(self) -> None:
        repo = InMemoryAttackGraphRepository()
        g = _graph(["prompt_injection"])
        await repo.save(g)
        fetched = await repo.get(g.id)
        assert fetched is not None
        assert fetched.id == g.id

    @pytest.mark.asyncio
    async def test_get_missing_returns_none(self) -> None:
        repo = InMemoryAttackGraphRepository()
        result = await repo.get("nonexistent")
        assert result is None


# ─── _max_severity_from_result ───────────────────────────────────────────────

class TestMaxSeverityFromResult:
    def _make_result(self, priorities: list[str]) -> object:
        @dataclass
        class MockPriority:
            value: str

        @dataclass
        class MockRiskIncident:
            priority: MockPriority

        @dataclass
        class MockResult:
            risk_incidents: list[MockRiskIncident]

        return MockResult(
            risk_incidents=[MockRiskIncident(MockPriority(p)) for p in priorities]
        )

    def test_critical_wins(self) -> None:
        result = self._make_result(["low", "critical", "high"])
        assert _max_severity_from_result(result) == "critical"  # type: ignore[arg-type]

    def test_empty_returns_none(self) -> None:
        result = self._make_result([])
        assert _max_severity_from_result(result) is None  # type: ignore[arg-type]

    def test_all_low(self) -> None:
        result = self._make_result(["low", "low"])
        assert _max_severity_from_result(result) == "low"  # type: ignore[arg-type]


# ─── RedTeamOrchestrator (mocked ValidationService) ──────────────────────────

def _make_validation_service(
    findings: int = 0,
    severity: str | None = None,
    fail: bool = False,
) -> MagicMock:
    """Build a mock ValidationService that returns results with specified findings."""
    @dataclass
    class MockPriority:
        value: str

    @dataclass
    class MockRiskIncident:
        priority: MockPriority
        incident_id: str = "ri-001"

    @dataclass
    class MockVSResult:
        status: str
        finding_ids: list[str]
        evidence_ids: list[str]
        risk_incidents: list[MockRiskIncident]
        findings_count: int
        failure_reason: str | None = None

    finding_ids = [f"f-{i}" for i in range(findings)]
    result = MockVSResult(
        status="failed" if fail else "completed",
        finding_ids=finding_ids,
        evidence_ids=[],
        risk_incidents=[MockRiskIncident(MockPriority(severity))] if severity else [],
        findings_count=findings,
        failure_reason="mock failure" if fail else None,
    )
    svc = MagicMock()
    svc.execute = AsyncMock(return_value=result)
    return svc


class TestRedTeamOrchestrator:
    def _request(
        self,
        cats: list[str],
        criteria: GoalCriteria = GoalCriteria.ALL_COMPLETE,
        **kw: object,
    ) -> RedTeamRequest:
        return RedTeamRequest(
            organization_id=ORG,
            target_id="tgt-001",
            target_endpoint="http://test",
            target_provider="openai",
            target_name="TestModel",
            model="gpt-4o",
            target_system_prompt="",
            goal=_goal(cats, criteria, **kw),
            correlation_id="corr-001",
            campaign_id=CAMPAIGN,
        )

    @pytest.mark.asyncio
    async def test_execute_single_node(self) -> None:
        svc = _make_validation_service(findings=0)
        orch = RedTeamOrchestrator(validation_service=svc)
        req = self._request(["prompt_injection"])
        result = await orch.execute(req)
        assert result.total_nodes == 1
        assert result.completed_nodes == 1
        assert result.state == AttackGraphState.COMPLETED

    @pytest.mark.asyncio
    async def test_execute_stops_on_first_finding(self) -> None:
        svc = _make_validation_service(findings=1, severity="high")
        orch = RedTeamOrchestrator(validation_service=svc)
        req = self._request(
            ["a", "b", "c"],
            GoalCriteria.FIRST_FINDING,
        )
        result = await orch.execute(req)
        assert result.goal_achieved
        assert result.state == AttackGraphState.GOAL_ACHIEVED

    @pytest.mark.asyncio
    async def test_execute_all_complete(self) -> None:
        svc = _make_validation_service(findings=0)
        orch = RedTeamOrchestrator(validation_service=svc)
        req = self._request(["a", "b", "c"], GoalCriteria.ALL_COMPLETE)
        result = await orch.execute(req)
        assert result.total_nodes == 3
        assert result.completed_nodes == 3
        assert not result.goal_achieved

    @pytest.mark.asyncio
    async def test_success_rate_property(self) -> None:
        svc = _make_validation_service(findings=0)
        orch = RedTeamOrchestrator(validation_service=svc)
        req = self._request(["a", "b"], GoalCriteria.ALL_COMPLETE)
        result = await orch.execute(req)
        assert result.success_rate == 100.0

    @pytest.mark.asyncio
    async def test_pause_and_resume_via_orchestrator(self) -> None:
        repo = InMemoryAttackGraphRepository()
        svc = _make_validation_service(findings=0)
        orch = RedTeamOrchestrator(validation_service=svc, graph_repository=repo)
        req = self._request(["a"])
        result = await orch.execute(req)
        graph_id = result.graph_id
        # Graph is terminal (COMPLETED) — pause should raise
        with pytest.raises(AttackGraphNotRunningError):
            await orch.pause(graph_id)

    @pytest.mark.asyncio
    async def test_cancel_running_graph(self) -> None:
        repo = InMemoryAttackGraphRepository()
        svc = _make_validation_service(findings=0)
        orch = RedTeamOrchestrator(validation_service=svc, graph_repository=repo)
        # Inject a pre-built graph that is RUNNING
        g = _graph(["a", "b", "c"])
        g.collect_events()
        orch._active_graphs[g.id] = g
        await repo.save(g)
        await orch.cancel(g.id, reason="test")
        assert g.state == AttackGraphState.CANCELLED

    @pytest.mark.asyncio
    async def test_retry_failed_nodes(self) -> None:
        repo = InMemoryAttackGraphRepository()
        svc = _make_validation_service(findings=0)
        orch = RedTeamOrchestrator(validation_service=svc, graph_repository=repo)
        g = _graph(["a", "b"])
        g.collect_events()
        g.mark_node_running("node_0_a")
        g.mark_node_failed("node_0_a", failure_reason="err", duration_ms=5)
        g.collect_events()
        orch._active_graphs[g.id] = g
        await repo.save(g)

        req = self._request(["a", "b"])
        result = await orch.retry_failed(g.id, req)
        assert result is not None

    @pytest.mark.asyncio
    async def test_execute_max_duration_override(self) -> None:
        svc = _make_validation_service(findings=0)
        orch = RedTeamOrchestrator(validation_service=svc)
        req = RedTeamRequest(
            organization_id=ORG,
            target_id="tgt",
            target_endpoint="http://test",
            target_provider="openai",
            target_name="M",
            model="gpt-4o",
            target_system_prompt="",
            goal=_goal(["a"]),
            correlation_id="c",
            campaign_id="camp",
            max_duration_s=3600,
        )
        result = await orch.execute(req)
        assert result.total_nodes == 1

    @pytest.mark.asyncio
    async def test_knowledge_graph_projection(self) -> None:
        svc = _make_validation_service(findings=0)
        kg = MagicMock()
        kg.add_node = MagicMock()
        kg.add_relationship = MagicMock()
        orch = RedTeamOrchestrator(validation_service=svc, knowledge_graph=kg)
        req = self._request(["prompt_injection"])
        await orch.execute(req)
        assert kg.add_node.call_count >= 1

    @pytest.mark.asyncio
    async def test_retry_cross_tenant_rejected(self) -> None:
        """retry_failed must reject requests where org_id doesn't match graph."""
        repo = InMemoryAttackGraphRepository()
        svc = _make_validation_service(findings=0)
        orch = RedTeamOrchestrator(validation_service=svc, graph_repository=repo)
        g = _graph(["a"])
        g.collect_events()
        g.mark_node_running("node_0_a")
        g.mark_node_failed("node_0_a", failure_reason="err", duration_ms=5)
        g.collect_events()
        orch._active_graphs[g.id] = g
        await repo.save(g)

        # Retry with a DIFFERENT org
        wrong_org_req = RedTeamRequest(
            organization_id="evil-org",
            target_id="tgt",
            target_endpoint="http://test",
            target_provider="openai",
            target_name="M",
            model="gpt-4o",
            target_system_prompt="",
            goal=_goal(["a"]),
            correlation_id="c",
            campaign_id="camp",
        )
        with pytest.raises(PermissionError):
            await orch.retry_failed(g.id, wrong_org_req)

    @pytest.mark.asyncio
    async def test_pause_cross_tenant_rejected(self) -> None:
        """pause must reject requests where org_id doesn't match graph."""
        repo = InMemoryAttackGraphRepository()
        svc = _make_validation_service(findings=0)
        orch = RedTeamOrchestrator(validation_service=svc, graph_repository=repo)
        g = _graph(["a", "b"])
        orch._active_graphs[g.id] = g
        await repo.save(g)
        with pytest.raises(PermissionError):
            await orch.pause(g.id, organization_id="evil-org")

    @pytest.mark.asyncio
    async def test_cancel_cross_tenant_rejected(self) -> None:
        """cancel must reject requests where org_id doesn't match graph."""
        repo = InMemoryAttackGraphRepository()
        svc = _make_validation_service(findings=0)
        orch = RedTeamOrchestrator(validation_service=svc, graph_repository=repo)
        g = _graph(["a", "b"])
        orch._active_graphs[g.id] = g
        await repo.save(g)
        with pytest.raises(PermissionError):
            await orch.cancel(g.id, organization_id="evil-org")


# ─── Large campaign simulation ────────────────────────────────────────────────

class TestLargeCampaign:
    @pytest.mark.asyncio
    async def test_23_attack_categories(self) -> None:
        cats = [
            "prompt_injection", "indirect_prompt_injection", "rag_poisoning",
            "memory_poisoning", "tool_abuse", "function_calling_abuse",
            "mcp_tool_abuse", "agent_escalation", "cross_agent_attacks",
            "multi_agent_collaboration_abuse", "conversation_hijacking",
            "context_manipulation", "system_prompt_extraction", "policy_bypass",
            "role_escalation", "instruction_override", "data_exfiltration",
            "secret_leakage", "hallucination_safety", "reasoning_manipulation",
            "long_context_abuse", "model_confusion", "cross_provider_behaviour",
        ]
        assert len(cats) == 23
        svc = _make_validation_service(findings=0)
        orch = RedTeamOrchestrator(validation_service=svc)
        req = RedTeamRequest(
            organization_id=ORG,
            target_id="tgt",
            target_endpoint="http://test",
            target_provider="openai",
            target_name="M",
            model="gpt-4o",
            target_system_prompt="",
            goal=_goal(cats),
            correlation_id="c",
            campaign_id="camp",
        )
        result = await orch.execute(req)
        assert result.total_nodes == 23
        assert result.completed_nodes == 23

    @pytest.mark.asyncio
    async def test_parallel_nodes_respected(self) -> None:
        """Max parallel nodes limits concurrent executions."""
        cats = [f"cat_{i}" for i in range(10)]
        svc = _make_validation_service(findings=0)
        orch = RedTeamOrchestrator(validation_service=svc)
        req = RedTeamRequest(
            organization_id=ORG,
            target_id="tgt",
            target_endpoint="http://test",
            target_provider="openai",
            target_name="M",
            model="gpt-4o",
            target_system_prompt="",
            goal=_goal(cats),
            correlation_id="c",
            campaign_id="camp",
            max_parallel_nodes=2,
        )
        result = await orch.execute(req)
        assert result.total_nodes == 10
        assert result.completed_nodes == 10
