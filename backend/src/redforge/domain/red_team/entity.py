"""AttackGraph aggregate — Sprint 34/35.

The AttackGraph is the RUNTIME EXECUTION STATE MACHINE for a goal-oriented
red team campaign. It is NOT the AttackPlan (which selects what attacks to
run). It tracks which nodes have run, which are ready, what evidence was
produced, and whether the campaign goal has been achieved.

Design invariants:
- Nodes transition forward-only: PENDING → READY → RUNNING → (COMPLETED | FAILED)
                                  PENDING → BLOCKED (dependency failed)
                                  PENDING/READY → SKIPPED (conditional edge false)
- The graph is a DAG — cycles are rejected at construction time.
- Goal evaluation happens after every node reaches a terminal state.
- The graph is PAUSED/RESUMED/CANCELLED atomically — no partial pause.
- All mutation methods return the new event list (collect-and-clear pattern).

This aggregate lives in the DOMAIN layer — no infrastructure imports.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from redforge.domain.red_team.events import (
    AttackGraphCancelled,
    AttackGraphCompleted,
    AttackGraphCreated,
    AttackGraphPaused,
    AttackGraphResumed,
    AttackNodeBlocked,
    AttackNodeCompleted,
    AttackNodeFailed,
    AttackNodeInjected,
    AttackNodeReady,
    AttackNodeSkipped,
    AttackNodeStarted,
    BudgetExhausted,
    GoalAchieved,
    RedTeamEvent,
)
from redforge.domain.red_team.exceptions import (
    AttackGraphAlreadyTerminalError,
    AttackGraphCycleError,
    AttackGraphNotRunningError,
    AttackNodeNotFoundError,
    BudgetExhaustedError,
    GoalAchievedSignal,
)
from redforge.domain.red_team.value_objects import (
    AttackEdge,
    AttackGraphState,
    AttackNodeResult,
    AttackNodeState,
    CampaignGoal,
    EdgeCondition,
    GoalCriteria,
)

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0,
}


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class AttackGraph:
    """Mutable runtime execution state machine for a red team campaign.

    Constructed via `AttackGraph.create()`. All internal mutable state is
    tracked here; callers collect domain events via `collect_events()`.
    """

    _id: str
    _organization_id: str
    _campaign_id: str
    _goal: CampaignGoal
    # node_id → attack_category (immutable structure built at creation)
    _nodes: dict[str, str]
    # dependency edges: to_node_id → list of (from_node_id, EdgeCondition)
    _dependencies: dict[str, list[tuple[str, EdgeCondition]]]
    # node_id → result (mutable)
    _results: dict[str, AttackNodeResult]
    _graph_state: AttackGraphState
    _goal_achieved: bool
    _goal_achieved_at: datetime | None
    _started_at: datetime
    _completed_at: datetime | None
    _execution_order: list[str]   # topological order computed at creation
    _nodes_executed: int
    _total_findings: int
    _events: list[RedTeamEvent]
    _start_ms: float              # monotonic reference for duration tracking

    # ── Constructor ──────────────────────────────────────────────────────────

    @classmethod
    def create(
        cls,
        graph_id: str,
        organization_id: str,
        campaign_id: str,
        goal: CampaignGoal,
        attack_categories: list[str],
        edges: list[AttackEdge] | None = None,
    ) -> AttackGraph:
        """Build an AttackGraph from a list of attack categories and optional edges.

        Each attack category becomes one node. Edges encode dependencies.
        The topological order is computed via Kahn's algorithm at construction;
        if a cycle is detected, `AttackGraphCycleError` is raised.

        Args:
            graph_id: Unique identifier for this graph instance.
            organization_id: Owning organization (from JWT TenantContext).
            campaign_id: The owning campaign.
            goal: Goal + budget constraints governing execution.
            attack_categories: Ordered list of category names; each becomes a node.
            edges: Optional dependency edges between node_ids.

        Returns:
            A new AttackGraph in RUNNING state with all nodes PENDING.
        """
        if not attack_categories:
            raise ValueError("attack_categories must not be empty")

        edges = edges or []
        node_ids = [f"node_{i}_{cat}" for i, cat in enumerate(attack_categories)]
        nodes: dict[str, str] = dict(zip(node_ids, attack_categories, strict=False))

        # Validate all edge endpoints refer to known nodes
        node_id_set = set(node_ids)
        for edge in edges:
            if edge.from_node_id not in node_id_set:
                raise AttackNodeNotFoundError(edge.from_node_id)
            if edge.to_node_id not in node_id_set:
                raise AttackNodeNotFoundError(edge.to_node_id)

        # Build adjacency for cycle detection and topological sort
        # Kahn's algorithm on the dependency graph
        in_degree: dict[str, int] = {nid: 0 for nid in node_ids}
        # successors: from_node → [to_node] (for Kahn's)
        successors: dict[str, list[str]] = defaultdict(list)
        # dependencies: to_node → [(from_node, condition)]
        deps: dict[str, list[tuple[str, EdgeCondition]]] = defaultdict(list)
        for edge in edges:
            successors[edge.from_node_id].append(edge.to_node_id)
            deps[edge.to_node_id].append((edge.from_node_id, edge.condition))
            in_degree[edge.to_node_id] += 1

        # Kahn's topological sort
        queue: deque[str] = deque(nid for nid, d in in_degree.items() if d == 0)
        topo: list[str] = []
        remaining_in_degree = dict(in_degree)
        while queue:
            nid = queue.popleft()
            topo.append(nid)
            for succ in successors.get(nid, []):
                remaining_in_degree[succ] -= 1
                if remaining_in_degree[succ] == 0:
                    queue.append(succ)
        if len(topo) != len(node_ids):
            raise AttackGraphCycleError(
                "Attack dependency graph contains a cycle — cannot create AttackGraph"
            )

        results: dict[str, AttackNodeResult] = {
            nid: AttackNodeResult(node_id=nid, attack_category=cat)
            for nid, cat in nodes.items()
        }

        # Nodes with no dependencies start as READY immediately
        for nid in node_ids:
            if nid not in deps or not deps[nid]:
                results[nid].state = AttackNodeState.READY

        now = _utc_now()
        graph = cls(
            _id=graph_id,
            _organization_id=organization_id,
            _campaign_id=campaign_id,
            _goal=goal,
            _nodes=nodes,
            _dependencies=dict(deps),
            _results=results,
            _graph_state=AttackGraphState.RUNNING,
            _goal_achieved=False,
            _goal_achieved_at=None,
            _started_at=now,
            _completed_at=None,
            _execution_order=topo,
            _nodes_executed=0,
            _total_findings=0,
            _events=[],
            _start_ms=time.monotonic(),
        )
        graph._events.append(AttackGraphCreated(
            campaign_id=campaign_id,
            graph_id=graph_id,
            organization_id=organization_id,
            occurred_at=now,
            node_count=len(node_ids),
            objective_name=goal.objective.name,
            attack_categories=tuple(attack_categories),
        ))
        return graph

    # ── State queries ─────────────────────────────────────────────────────────

    @property
    def id(self) -> str:
        return self._id

    @property
    def organization_id(self) -> str:
        return self._organization_id

    @property
    def campaign_id(self) -> str:
        return self._campaign_id

    @property
    def goal(self) -> CampaignGoal:
        return self._goal

    @property
    def state(self) -> AttackGraphState:
        return self._graph_state

    @property
    def goal_achieved(self) -> bool:
        return self._goal_achieved

    @property
    def is_running(self) -> bool:
        return self._graph_state == AttackGraphState.RUNNING

    @property
    def is_terminal(self) -> bool:
        return self._graph_state in (
            AttackGraphState.GOAL_ACHIEVED,
            AttackGraphState.COMPLETED,
            AttackGraphState.FAILED,
            AttackGraphState.CANCELLED,
        )

    @property
    def ready_nodes(self) -> list[str]:
        """Node IDs that are in READY state and can be executed."""
        return [
            nid for nid, res in self._results.items()
            if res.state == AttackNodeState.READY
        ]

    @property
    def all_terminal(self) -> bool:
        """True when every node has reached a terminal state."""
        return all(r.is_terminal for r in self._results.values())

    @property
    def nodes_executed(self) -> int:
        return self._nodes_executed

    @property
    def total_findings(self) -> int:
        return self._total_findings

    @property
    def execution_order(self) -> list[str]:
        return list(self._execution_order)

    def node_result(self, node_id: str) -> AttackNodeResult:
        if node_id not in self._results:
            raise AttackNodeNotFoundError(node_id)
        return self._results[node_id]

    def all_results(self) -> list[AttackNodeResult]:
        return list(self._results.values())

    def attack_category_for(self, node_id: str) -> str:
        if node_id not in self._nodes:
            raise AttackNodeNotFoundError(node_id)
        return self._nodes[node_id]

    # ── Transitions ───────────────────────────────────────────────────────────

    def mark_node_running(self, node_id: str) -> None:
        """Transition a READY node to RUNNING."""
        self._assert_running()
        result = self._get_result(node_id)
        if result.state != AttackNodeState.READY:
            raise ValueError(
                f"Node {node_id!r} is {result.state.value}, not READY — cannot start"
            )
        result.state = AttackNodeState.RUNNING
        self._events.append(AttackNodeStarted(
            campaign_id=self._campaign_id,
            graph_id=self._id,
            organization_id=self._organization_id,
            node_id=node_id,
            attack_category=self._nodes[node_id],
        ))

    def mark_node_completed(
        self,
        node_id: str,
        evidence_ids: list[str],
        finding_ids: list[str],
        risk_incident_ids: list[str],
        duration_ms: int,
        max_severity_found: str | None = None,
    ) -> None:
        """Transition a RUNNING node to COMPLETED and update successors."""
        self._assert_running()
        result = self._get_result(node_id)
        if result.state != AttackNodeState.RUNNING:
            raise ValueError(
                f"Node {node_id!r} is {result.state.value}, not RUNNING"
            )
        result.state = AttackNodeState.COMPLETED
        result.evidence_ids = evidence_ids
        result.finding_ids = finding_ids
        result.risk_incident_ids = risk_incident_ids
        result.duration_ms = duration_ms
        result.findings_count = len(finding_ids)
        result.max_severity_found = max_severity_found

        self._nodes_executed += 1
        self._total_findings += len(finding_ids)

        self._events.append(AttackNodeCompleted(
            campaign_id=self._campaign_id,
            graph_id=self._id,
            organization_id=self._organization_id,
            node_id=node_id,
            attack_category=self._nodes[node_id],
            findings_count=len(finding_ids),
            evidence_count=len(evidence_ids),
            duration_ms=duration_ms,
        ))

        # Update successors based on dependency conditions
        self._propagate(node_id, succeeded=True)
        # Check goal + budget
        self._check_goal_and_budget(triggering_node_id=node_id)

    def mark_node_failed(
        self,
        node_id: str,
        failure_reason: str,
        duration_ms: int = 0,
    ) -> None:
        """Transition a RUNNING node to FAILED and propagate to successors."""
        self._assert_running()
        result = self._get_result(node_id)
        if result.state != AttackNodeState.RUNNING:
            raise ValueError(
                f"Node {node_id!r} is {result.state.value}, not RUNNING"
            )
        result.state = AttackNodeState.FAILED
        result.failure_reason = failure_reason
        result.duration_ms = duration_ms

        self._nodes_executed += 1

        self._events.append(AttackNodeFailed(
            campaign_id=self._campaign_id,
            graph_id=self._id,
            organization_id=self._organization_id,
            node_id=node_id,
            attack_category=self._nodes[node_id],
            failure_reason=failure_reason,
        ))

        self._propagate(node_id, succeeded=False)
        # Natural completion is deferred: orchestrator calls try_complete() after
        # the adaptive intelligence layer has had a chance to act on the failure.

    def pause(self) -> None:
        """Pause the graph; in-flight nodes run to completion."""
        self._assert_running()
        self._graph_state = AttackGraphState.PAUSED
        pending = sum(
            1 for r in self._results.values()
            if r.state in (AttackNodeState.PENDING, AttackNodeState.READY)
        )
        self._events.append(AttackGraphPaused(
            campaign_id=self._campaign_id,
            graph_id=self._id,
            organization_id=self._organization_id,
            pending_nodes=pending,
        ))

    def resume(self) -> None:
        """Resume a PAUSED graph."""
        if self._graph_state != AttackGraphState.PAUSED:
            raise AttackGraphNotRunningError(
                f"AttackGraph {self._id!r} is {self._graph_state.value}, not PAUSED"
            )
        self._graph_state = AttackGraphState.RUNNING
        self._events.append(AttackGraphResumed(
            campaign_id=self._campaign_id,
            graph_id=self._id,
            organization_id=self._organization_id,
        ))

    def cancel(self, reason: str) -> None:
        """Cancel the graph immediately."""
        if self.is_terminal:
            raise AttackGraphAlreadyTerminalError(
                f"AttackGraph {self._id!r} is already terminal ({self._graph_state.value})"
            )
        self._graph_state = AttackGraphState.CANCELLED
        self._completed_at = _utc_now()
        self._events.append(AttackGraphCancelled(
            campaign_id=self._campaign_id,
            graph_id=self._id,
            organization_id=self._organization_id,
            reason=reason,
        ))

    def inject_node(
        self,
        node_id: str,
        attack_category: str,
        decision_id: str,
        reason: str,
    ) -> None:
        """Inject a new leaf node (no dependencies) into the running graph.

        Injected nodes are immediately READY — they have no edges to or from
        existing nodes, so no cycle is possible and no dependency evaluation
        is needed. This is called by the adaptive intelligence layer when it
        decides to ESCALATE or BRANCH.

        Only valid while the graph is RUNNING (or PAUSED — injected nodes will
        become available on resume).

        Raises:
            AttackGraphAlreadyTerminalError: if the graph has already completed.
            ValueError: if node_id already exists in the graph.
        """
        if self.is_terminal:
            raise AttackGraphAlreadyTerminalError(
                f"AttackGraph {self._id!r} is terminal — cannot inject node"
            )
        if node_id in self._nodes:
            raise ValueError(
                f"Node {node_id!r} already exists in AttackGraph {self._id!r}"
            )
        self._nodes[node_id] = attack_category
        self._execution_order.append(node_id)
        result = AttackNodeResult(
            node_id=node_id,
            attack_category=attack_category,
            state=AttackNodeState.READY,
        )
        self._results[node_id] = result
        self._events.append(AttackNodeInjected(
            campaign_id=self._campaign_id,
            graph_id=self._id,
            organization_id=self._organization_id,
            node_id=node_id,
            attack_category=attack_category,
            triggering_decision_id=decision_id,
            injection_reason=reason,
        ))

    def try_complete(self) -> bool:
        """Finalize the graph if all nodes have reached a terminal state.

        Called by the orchestrator AFTER consulting the adaptive intelligence
        layer. This separation is critical: intelligence may inject new nodes
        (via inject_node()) between the last node completing and this call,
        so the graph must not auto-finalize inside mark_node_completed().

        Returns True if the graph transitioned to COMPLETED this call.
        Idempotent — safe to call multiple times.
        """
        if self.is_terminal:
            return False
        already_terminal = self._graph_state
        self._check_completion()
        return self.is_terminal and self._graph_state != already_terminal

    def reset_failed_nodes(self) -> list[str]:
        """Reset FAILED nodes to READY for retry. Returns list of reset node IDs.

        Only resets nodes whose dependencies are all satisfied (i.e., predecessors
        are in COMPLETED or SKIPPED state — not FAILED or BLOCKED).
        """
        if self.is_terminal:
            raise AttackGraphAlreadyTerminalError(
                f"AttackGraph {self._id!r} is terminal — cannot retry"
            )
        if self._graph_state != AttackGraphState.RUNNING:
            raise AttackGraphNotRunningError(
                f"AttackGraph {self._id!r} must be RUNNING to retry"
            )
        reset: list[str] = []
        for nid, result in self._results.items():
            if result.state != AttackNodeState.FAILED:
                continue
            if self._dependencies_satisfied(nid):
                result.state = AttackNodeState.READY
                result.failure_reason = None
                result.evidence_ids = []
                result.finding_ids = []
                result.risk_incident_ids = []
                result.duration_ms = 0
                result.findings_count = 0
                result.max_severity_found = None
                self._events.append(AttackNodeReady(
                    campaign_id=self._campaign_id,
                    graph_id=self._id,
                    organization_id=self._organization_id,
                    node_id=nid,
                    attack_category=self._nodes[nid],
                ))
                reset.append(nid)
        return reset

    # ── Event collection ──────────────────────────────────────────────────────

    def collect_events(self) -> list[RedTeamEvent]:
        """Return and clear the pending event list."""
        events = list(self._events)
        self._events.clear()
        return events

    # ── Private helpers ───────────────────────────────────────────────────────

    def _assert_running(self) -> None:
        if self._graph_state == AttackGraphState.PAUSED:
            # Allow node completions to propagate even while PAUSED
            return
        if not self.is_running:
            raise AttackGraphNotRunningError(
                f"AttackGraph {self._id!r} is {self._graph_state.value}"
            )

    def _get_result(self, node_id: str) -> AttackNodeResult:
        if node_id not in self._results:
            raise AttackNodeNotFoundError(node_id)
        return self._results[node_id]

    def _propagate(self, completed_node_id: str, succeeded: bool) -> None:
        """Update PENDING successors whose only dependency was this node."""
        for nid, deps in self._dependencies.items():
            result = self._results[nid]
            if result.is_terminal or result.state == AttackNodeState.RUNNING:
                continue
            for from_nid, condition in deps:
                if from_nid != completed_node_id:
                    continue
                # Check if this dependency's condition is satisfied
                if not self._condition_satisfied(condition, succeeded):
                    # Condition not met: block/skip this node if it was depending on it
                    if condition == EdgeCondition.ON_SUCCESS and not succeeded:
                        result.state = AttackNodeState.BLOCKED
                        result.failure_reason = f"Blocked: dependency {from_nid!r} failed"
                        self._events.append(AttackNodeBlocked(
                            campaign_id=self._campaign_id,
                            graph_id=self._id,
                            organization_id=self._organization_id,
                            node_id=nid,
                            blocking_node_id=from_nid,
                        ))
                    elif condition == EdgeCondition.ON_FAILURE and succeeded:
                        result.state = AttackNodeState.SKIPPED
                        self._events.append(AttackNodeSkipped(
                            campaign_id=self._campaign_id,
                            graph_id=self._id,
                            organization_id=self._organization_id,
                            node_id=nid,
                            attack_category=self._nodes[nid],
                            reason=f"Skip condition: dependency {from_nid!r} succeeded",
                        ))
            # After all edges processed, re-check if now READY
            if (result.state == AttackNodeState.PENDING
                    and self._dependencies_satisfied(nid)):
                result.state = AttackNodeState.READY
                self._events.append(AttackNodeReady(
                    campaign_id=self._campaign_id,
                    graph_id=self._id,
                    organization_id=self._organization_id,
                    node_id=nid,
                    attack_category=self._nodes[nid],
                ))

    def _dependencies_satisfied(self, node_id: str) -> bool:
        """Return True if all ON_SUCCESS deps completed or all deps are terminal."""
        for from_nid, condition in self._dependencies.get(node_id, []):
            from_result = self._results[from_nid]
            if not from_result.is_terminal:
                return False
            if (condition == EdgeCondition.ON_SUCCESS
                    and from_result.state != AttackNodeState.COMPLETED):
                return False
            if (condition == EdgeCondition.ON_FAILURE
                    and from_result.state != AttackNodeState.FAILED):
                return False
        return True

    @staticmethod
    def _condition_satisfied(condition: EdgeCondition, succeeded: bool) -> bool:
        if condition == EdgeCondition.ON_SUCCESS:
            return succeeded
        if condition == EdgeCondition.ON_FAILURE:
            return not succeeded
        return True  # ALWAYS

    def _check_goal_and_budget(self, triggering_node_id: str) -> None:
        """Evaluate goal criteria and budget constraints after a node completes."""
        obj = self._goal.objective
        budget = self._goal.budget
        criteria = obj.goal_criteria

        # Budget checks (take priority over goal)
        if budget.max_nodes is not None and self._nodes_executed >= budget.max_nodes:
            self._terminate_budget("max_nodes", budget.max_nodes)
            return
        if budget.max_findings is not None and self._total_findings >= budget.max_findings:
            self._terminate_budget("max_findings", budget.max_findings)
            return

        # Goal checks
        goal_met = False
        if criteria == GoalCriteria.FIRST_FINDING and self._total_findings > 0:
            goal_met = True
        elif criteria == GoalCriteria.FINDING_COUNT:
            goal_met = self._total_findings >= obj.finding_count_threshold
        elif criteria == GoalCriteria.SEVERITY_THRESHOLD:
            threshold_rank = _SEVERITY_RANK.get(obj.severity_threshold, 3)
            goal_met = any(
                _SEVERITY_RANK.get(r.max_severity_found or "", -1) >= threshold_rank
                for r in self._results.values()
                if r.state == AttackNodeState.COMPLETED
            )
        elif criteria == GoalCriteria.COVERAGE_THRESHOLD:
            completed_cats = {
                self._nodes[nid]
                for nid, r in self._results.items()
                if r.state == AttackNodeState.COMPLETED
            }
            all_cats = set(self._nodes.values())
            pct = (len(completed_cats) / len(all_cats)) * 100.0 if all_cats else 0.0
            goal_met = pct >= obj.coverage_threshold_pct

        if goal_met:
            self._graph_state = AttackGraphState.GOAL_ACHIEVED
            self._goal_achieved = True
            self._goal_achieved_at = _utc_now()
            self._completed_at = self._goal_achieved_at
            self._events.append(GoalAchieved(
                campaign_id=self._campaign_id,
                graph_id=self._id,
                organization_id=self._organization_id,
                objective_name=obj.name,
                achieved_by_node_id=triggering_node_id,
                total_findings=self._total_findings,
                total_nodes_executed=self._nodes_executed,
            ))
            raise GoalAchievedSignal(triggering_node_id, self._total_findings)

        # Natural completion is deferred: orchestrator calls try_complete() after
        # the adaptive intelligence layer has had a chance to inject new nodes.

    def _terminate_budget(self, limit_type: str, limit_value: int) -> None:
        self._graph_state = AttackGraphState.COMPLETED
        self._completed_at = _utc_now()
        self._events.append(BudgetExhausted(
            campaign_id=self._campaign_id,
            graph_id=self._id,
            organization_id=self._organization_id,
            limit_type=limit_type,
            limit_value=limit_value,
            nodes_executed=self._nodes_executed,
        ))
        raise BudgetExhaustedError(limit_type, limit_value)

    def _check_completion(self) -> None:
        if not self.all_terminal:
            return
        if self.is_terminal:
            return
        completed = sum(1 for r in self._results.values() if r.state == AttackNodeState.COMPLETED)
        failed = sum(1 for r in self._results.values() if r.state == AttackNodeState.FAILED)
        blocked = sum(1 for r in self._results.values() if r.state == AttackNodeState.BLOCKED)
        skipped = sum(1 for r in self._results.values() if r.state == AttackNodeState.SKIPPED)
        duration_ms = int((time.monotonic() - self._start_ms) * 1000)
        self._graph_state = AttackGraphState.COMPLETED
        self._completed_at = _utc_now()
        self._events.append(AttackGraphCompleted(
            campaign_id=self._campaign_id,
            graph_id=self._id,
            organization_id=self._organization_id,
            total_nodes=len(self._nodes),
            completed_nodes=completed,
            failed_nodes=failed,
            blocked_nodes=blocked,
            skipped_nodes=skipped,
            goal_achieved=self._goal_achieved,
            total_findings=self._total_findings,
            duration_ms=duration_ms,
        ))

    def summary(self) -> dict[str, Any]:
        """Return a human-readable summary dict for logging and API responses."""
        return {
            "graph_id": self._id,
            "campaign_id": self._campaign_id,
            "state": self._graph_state.value,
            "goal_achieved": self._goal_achieved,
            "nodes_executed": self._nodes_executed,
            "total_findings": self._total_findings,
            "node_states": {
                nid: r.state.value for nid, r in self._results.items()
            },
        }
