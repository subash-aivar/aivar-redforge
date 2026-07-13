"""RedTeamOrchestrator — Sprint 34/35 (base) + Sprint 36/37 (adaptive).

Goal-Oriented AI Red Team Orchestration Engine — extended with the
Adaptive Campaign Intelligence Layer.

Sprint 36/37 additions:
- Optional CampaignIntelligenceService injection for adaptive decisions.
- After each node completes, the intelligence service is consulted.
- ESCALATE/BRANCH decisions inject new nodes via AttackGraph.inject_node().
- STOP decisions terminate the graph early (via cancel()).
- PIVOT/RETRY_WITH_VARIANT decisions are recorded in decision_history and
  the orchestrator adjusts the next ValidationServiceRequest accordingly.
- RedTeamResult now includes decision_history, intelligence_confidence,
  and injected_nodes count.
- Plugin SDK (PluginRegistry) is wired at construction time.

What this does NOT do:
- Does NOT reimplement ValidationService logic.
- Does NOT reimplement campaign lifecycle (Campaign aggregate still owns that).
- Does NOT reimplement risk correlation or KG population.
- Does NOT own the evidence/finding/risk domain — reuses it entirely.

Security:
- organization_id comes exclusively from RedTeamRequest (built from JWT).
- Never accepted from HTTP body or query parameters.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from redforge.application.red_team.campaign_intelligence import (
    CampaignDecisionHistory,
    CampaignIntelligenceServicePort,
)
from redforge.application.red_team.contracts import AttackGraphRepositoryPort
from redforge.core.logging import get_logger
from redforge.domain.red_team.campaign_decision import (
    CampaignDecisionAction,
    CampaignDecisionRecord,
    CampaignIntelligenceContext,
    NodeEvidenceSummary,
)
from redforge.domain.red_team.entity import AttackGraph
from redforge.domain.red_team.exceptions import (
    BudgetExhaustedError,
    GoalAchievedSignal,
)
from redforge.domain.red_team.value_objects import (
    AttackEdge,
    AttackGraphState,
    AttackNodeState,
    BudgetConstraint,
    CampaignGoal,
)

if TYPE_CHECKING:
    from redforge.application.knowledge_graph import KnowledgeGraph
    from redforge.application.red_team.plugin_sdk import PluginRegistry
    from redforge.application.validation_service import (
        ValidationService,
        ValidationServiceResult,
    )

logger = get_logger(__name__)

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0,
}


# ─── DTOs ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RedTeamRequest:
    """Everything RedTeamOrchestrator needs to start a campaign.

    organization_id MUST come from signed JWT TenantContext — never from
    HTTP request body or query parameters.
    """

    organization_id: str
    target_id: str
    target_endpoint: str
    target_provider: str
    target_name: str
    model: str
    target_system_prompt: str
    goal: CampaignGoal
    correlation_id: str
    campaign_id: str = ""              # optional — links to an existing Campaign
    target_capabilities: frozenset[str] = field(default_factory=frozenset)
    max_attacks_per_category: int = 2
    severity_minimum: str = "medium"
    max_parallel_nodes: int = 3        # max simultaneous node executions
    edges: list[AttackEdge] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    max_duration_s: int | None = None  # wall-clock budget override


@dataclass
class RedTeamNodeSummary:
    """Per-node execution summary included in RedTeamResult."""

    node_id: str
    attack_category: str
    state: str
    findings_count: int
    evidence_count: int
    duration_ms: int
    failure_reason: str | None


@dataclass
class RedTeamResult:
    """Complete result of a RedTeamOrchestrator execution.

    Sprint 36/37 additions:
    - decision_history: every adaptive decision made during the campaign.
    - intelligence_confidence: average confidence across all decisions.
    - injected_nodes: how many nodes were injected by the intelligence layer.
    """

    graph_id: str
    campaign_id: str
    organization_id: str
    state: str                         # AttackGraphState.value
    goal_achieved: bool
    objective_name: str
    total_nodes: int
    nodes_executed: int
    completed_nodes: int
    failed_nodes: int
    blocked_nodes: int
    skipped_nodes: int
    total_findings: int
    total_evidence: int
    all_finding_ids: list[str]
    all_evidence_ids: list[str]
    all_risk_incident_ids: list[str]
    duration_ms: int
    node_summaries: list[RedTeamNodeSummary]
    failure_reason: str | None = None
    decision_history: list[CampaignDecisionRecord] = field(default_factory=list)
    intelligence_confidence: float = 0.0
    injected_nodes: int = 0

    @property
    def success_rate(self) -> float:
        if self.total_nodes == 0:
            return 0.0
        return (self.completed_nodes / self.total_nodes) * 100.0


# ─── In-memory graph repository (default; swap for PostgreSQL in production) ──


class InMemoryAttackGraphRepository:
    """Default non-persistent repository for tests and development."""

    def __init__(self) -> None:
        self._store: dict[str, AttackGraph] = {}

    async def save(self, graph: AttackGraph) -> None:
        self._store[graph.id] = graph

    async def get(self, graph_id: str) -> AttackGraph | None:
        return self._store.get(graph_id)


# ─── Orchestrator ─────────────────────────────────────────────────────────────


class RedTeamOrchestrator:
    """Goal-Oriented AI Red Team Orchestration Engine.

    Composes existing engines:
    - ValidationService     — attack execution + evidence/finding/risk
    - KnowledgeGraph        — graph projection of campaign/attack/evidence
    - AttackGraphRepository — persists execution state

    Does NOT replace or duplicate CampaignEngine. Both coexist:
    - CampaignEngine: multi-target fan-out, drift detection, campaign lifecycle
    - RedTeamOrchestrator: single-target goal-oriented attack graph execution

    Thread safety: one orchestrator instance can handle concurrent
    campaigns safely because each `execute()` call owns its own AttackGraph.
    """

    def __init__(
        self,
        validation_service: ValidationService,
        graph_repository: AttackGraphRepositoryPort | None = None,
        knowledge_graph: KnowledgeGraph | None = None,
        campaign_intelligence: CampaignIntelligenceServicePort | None = None,
        plugin_registry: PluginRegistry | None = None,
    ) -> None:
        self._validation_service = validation_service
        self._graph_repo: AttackGraphRepositoryPort = (
            graph_repository or InMemoryAttackGraphRepository()
        )
        self._knowledge_graph = knowledge_graph
        self._campaign_intelligence = campaign_intelligence
        self._plugin_registry = plugin_registry
        self._active_graphs: dict[str, AttackGraph] = {}

    async def execute(self, request: RedTeamRequest) -> RedTeamResult:
        """Execute a goal-oriented red team campaign.

        Builds an AttackGraph from the CampaignGoal's target_categories,
        runs nodes in topological order (with limited parallelism), and
        stops as soon as the goal is achieved or budget exhausted.
        """
        t0 = time.monotonic()
        graph_id = str(uuid.uuid4())
        categories = sorted(request.goal.objective.target_categories)

        # Optionally override budget from request-level duration
        budget = request.goal.budget
        if request.max_duration_s is not None and budget.max_duration_s is None:
            budget = BudgetConstraint(
                max_nodes=budget.max_nodes,
                max_duration_s=request.max_duration_s,
                max_findings=budget.max_findings,
            )
            goal = CampaignGoal(objective=request.goal.objective, budget=budget)
        else:
            goal = request.goal

        graph = AttackGraph.create(
            graph_id=graph_id,
            organization_id=request.organization_id,
            campaign_id=request.campaign_id or graph_id,
            goal=goal,
            attack_categories=categories,
            edges=request.edges,
        )
        self._active_graphs[graph_id] = graph
        await self._graph_repo.save(graph)

        logger.info(
            "red_team_started",
            graph_id=graph_id,
            organization_id=request.organization_id,
            objective=request.goal.objective.name,
            node_count=len(categories),
        )

        all_finding_ids: list[str] = []
        all_evidence_ids: list[str] = []
        all_risk_incident_ids: list[str] = []
        failure_reason: str | None = None

        from redforge.application.red_team.campaign_intelligence import (
            CampaignDecisionHistory,
        )
        decision_history = CampaignDecisionHistory()

        try:
            await self._run_graph(
                graph=graph,
                request=request,
                all_finding_ids=all_finding_ids,
                all_evidence_ids=all_evidence_ids,
                all_risk_incident_ids=all_risk_incident_ids,
                decision_history=decision_history,
            )
        except GoalAchievedSignal:
            pass  # graph state already set to GOAL_ACHIEVED
        except BudgetExhaustedError:
            pass  # graph state already set to COMPLETED
        except Exception as exc:
            failure_reason = f"{type(exc).__name__}: {exc}"
            logger.error(
                "red_team_error",
                graph_id=graph_id,
                error=failure_reason,
            )
            if not graph.is_terminal:
                graph.cancel(f"Internal error: {failure_reason}")

        await self._graph_repo.save(graph)
        duration_ms = int((time.monotonic() - t0) * 1000)

        # Project to KnowledgeGraph if wired
        self._project_to_kg(graph, request, decision_history)

        # Collect final node summaries
        results_by_state = {
            AttackNodeState.COMPLETED: 0,
            AttackNodeState.FAILED: 0,
            AttackNodeState.BLOCKED: 0,
            AttackNodeState.SKIPPED: 0,
        }
        node_summaries: list[RedTeamNodeSummary] = []
        for r in graph.all_results():
            if r.state in results_by_state:
                results_by_state[r.state] += 1
            node_summaries.append(RedTeamNodeSummary(
                node_id=r.node_id,
                attack_category=r.attack_category,
                state=r.state.value,
                findings_count=r.findings_count,
                evidence_count=len(r.evidence_ids),
                duration_ms=r.duration_ms,
                failure_reason=r.failure_reason,
            ))

        logger.info(
            "red_team_completed",
            graph_id=graph_id,
            state=graph.state.value,
            goal_achieved=graph.goal_achieved,
            total_findings=graph.total_findings,
            nodes_executed=graph.nodes_executed,
            duration_ms=duration_ms,
        )

        return RedTeamResult(
            graph_id=graph_id,
            campaign_id=request.campaign_id or graph_id,
            organization_id=request.organization_id,
            state=graph.state.value,
            goal_achieved=graph.goal_achieved,
            objective_name=request.goal.objective.name,
            total_nodes=len(graph.all_results()),
            nodes_executed=graph.nodes_executed,
            completed_nodes=results_by_state[AttackNodeState.COMPLETED],
            failed_nodes=results_by_state[AttackNodeState.FAILED],
            blocked_nodes=results_by_state[AttackNodeState.BLOCKED],
            skipped_nodes=results_by_state[AttackNodeState.SKIPPED],
            total_findings=graph.total_findings,
            total_evidence=len(all_evidence_ids),
            all_finding_ids=all_finding_ids,
            all_evidence_ids=all_evidence_ids,
            all_risk_incident_ids=all_risk_incident_ids,
            duration_ms=duration_ms,
            node_summaries=node_summaries,
            failure_reason=failure_reason,
            decision_history=list(decision_history.all_records),
            intelligence_confidence=decision_history.average_confidence,
            injected_nodes=decision_history.total_injections,
        )

    async def pause(self, graph_id: str, organization_id: str = "") -> None:
        """Pause a running AttackGraph. In-flight nodes complete first."""
        graph = await self._graph_repo.get(graph_id)
        if graph is None:
            raise KeyError(f"AttackGraph {graph_id!r} not found")
        if organization_id and graph.organization_id != organization_id:
            raise PermissionError(f"AttackGraph {graph_id!r} does not belong to caller's org")
        graph.pause()
        await self._graph_repo.save(graph)
        logger.info("red_team_paused", graph_id=graph_id)

    async def resume(self, graph_id: str, organization_id: str = "") -> None:
        """Resume a PAUSED AttackGraph."""
        graph = await self._graph_repo.get(graph_id)
        if graph is None:
            raise KeyError(f"AttackGraph {graph_id!r} not found")
        if organization_id and graph.organization_id != organization_id:
            raise PermissionError(f"AttackGraph {graph_id!r} does not belong to caller's org")
        graph.resume()
        await self._graph_repo.save(graph)
        logger.info("red_team_resumed", graph_id=graph_id)

    async def cancel(
        self,
        graph_id: str,
        reason: str = "manual",
        organization_id: str = "",
    ) -> None:
        """Cancel a running or paused AttackGraph."""
        graph = await self._graph_repo.get(graph_id)
        if graph is None:
            raise KeyError(f"AttackGraph {graph_id!r} not found")
        if organization_id and graph.organization_id != organization_id:
            raise PermissionError(f"AttackGraph {graph_id!r} does not belong to caller's org")
        graph.cancel(reason)
        await self._graph_repo.save(graph)
        logger.info("red_team_cancelled", graph_id=graph_id, reason=reason)

    async def retry_failed(
        self,
        graph_id: str,
        request: RedTeamRequest,
    ) -> RedTeamResult:
        """Reset FAILED nodes and continue execution from where it left off.

        Resets only nodes whose dependencies are satisfied. Creates a new
        result from the updated graph run.
        """
        graph = await self._graph_repo.get(graph_id)
        if graph is None:
            raise KeyError(f"AttackGraph {graph_id!r} not found")
        if graph.organization_id != request.organization_id:
            raise PermissionError(
                f"AttackGraph {graph_id!r} belongs to a different organization"
            )
        reset_nodes = graph.reset_failed_nodes()
        if not reset_nodes:
            logger.info("red_team_retry_no_failed_nodes", graph_id=graph_id)
        await self._graph_repo.save(graph)

        # Continue execution
        all_finding_ids: list[str] = []
        all_evidence_ids: list[str] = []
        all_risk_incident_ids: list[str] = []
        from redforge.application.red_team.campaign_intelligence import (
            CampaignDecisionHistory,
        )
        decision_history = CampaignDecisionHistory()
        with contextlib.suppress(GoalAchievedSignal, BudgetExhaustedError):
            await self._run_graph(
                graph=graph,
                request=request,
                all_finding_ids=all_finding_ids,
                all_evidence_ids=all_evidence_ids,
                all_risk_incident_ids=all_risk_incident_ids,
                decision_history=decision_history,
            )

        await self._graph_repo.save(graph)
        return self._build_result_from_graph(
            graph, request, all_finding_ids, all_evidence_ids,
            all_risk_incident_ids, decision_history,
        )

    # ── Execution loop ────────────────────────────────────────────────────────

    async def _run_graph(
        self,
        graph: AttackGraph,
        request: RedTeamRequest,
        all_finding_ids: list[str],
        all_evidence_ids: list[str],
        all_risk_incident_ids: list[str],
        decision_history: CampaignDecisionHistory,
    ) -> None:
        """Topological execution loop with bounded parallelism.

        Picks READY nodes, executes up to max_parallel_nodes concurrently,
        waits for completions, and repeats until the graph is terminal.
        Raises GoalAchievedSignal or BudgetExhaustedError for early exit.
        """
        deadline: float | None = None
        if request.max_duration_s is not None:
            deadline = time.monotonic() + request.max_duration_s

        while not graph.is_terminal:
            # Wall-clock budget check
            if deadline is not None and time.monotonic() >= deadline:
                graph.cancel("max_duration_s budget exhausted")
                return

            # Skip execution while PAUSED — caller must resume()
            if graph.state == AttackGraphState.PAUSED:
                await asyncio.sleep(0.1)
                continue

            ready = graph.ready_nodes
            if not ready:
                if not graph.all_terminal:
                    # All non-terminal nodes are RUNNING or PENDING awaiting deps
                    await asyncio.sleep(0.05)
                    continue
                break

            batch = ready[: request.max_parallel_nodes]
            tasks = [
                asyncio.create_task(
                    self._execute_node(
                        graph=graph,
                        node_id=node_id,
                        request=request,
                        all_finding_ids=all_finding_ids,
                        all_evidence_ids=all_evidence_ids,
                        all_risk_incident_ids=all_risk_incident_ids,
                        decision_history=decision_history,
                    )
                )
                for node_id in batch
            ]

            # Wait for the batch; GoalAchievedSignal or BudgetExhaustedError
            # propagates through asyncio.gather (first_exception mode)
            try:
                await asyncio.gather(*tasks)
            except (GoalAchievedSignal, BudgetExhaustedError):
                # Cancel remaining tasks in the batch
                for task in tasks:
                    task.cancel()
                raise

    async def _execute_node(
        self,
        graph: AttackGraph,
        node_id: str,
        request: RedTeamRequest,
        all_finding_ids: list[str],
        all_evidence_ids: list[str],
        all_risk_incident_ids: list[str],
        decision_history: CampaignDecisionHistory,
    ) -> None:
        """Execute a single AttackGraph node by delegating to ValidationService.

        After the node completes, the campaign intelligence service is consulted
        (if wired). The decision is recorded in decision_history and acted upon:
        - ESCALATE / BRANCH / PIVOT: new nodes are injected into the graph.
        - STOP: the graph is cancelled.
        - CONTINUE / RETRY_WITH_VARIANT: logged, no structural change.
        """
        from redforge.application.validation_service import ValidationServiceRequest

        attack_category = graph.attack_category_for(node_id)
        graph.mark_node_running(node_id)

        t0 = time.monotonic()
        try:
            vs_request = ValidationServiceRequest(
                organization_id=request.organization_id,
                target_id=request.target_id,
                target_endpoint=request.target_endpoint,
                target_provider=request.target_provider,
                target_name=request.target_name,
                model=request.model,
                target_system_prompt=request.target_system_prompt,
                target_capabilities=request.target_capabilities,
                attack_categories=frozenset({attack_category}),
                correlation_id=f"{request.correlation_id}:{node_id}",
                max_attacks_per_category=request.max_attacks_per_category,
                severity_minimum=request.severity_minimum,
                trigger_type="red_team",
            )
            result = await self._validation_service.execute(vs_request)

        except Exception as exc:
            duration_ms = int((time.monotonic() - t0) * 1000)
            failure_msg = f"{type(exc).__name__}: {exc}"
            graph.mark_node_failed(
                node_id,
                failure_reason=failure_msg,
                duration_ms=duration_ms,
            )
            # Intelligence runs BEFORE graph finalizes so it can inject new nodes
            self._adapt_from_node_result(
                graph=graph,
                node_id=node_id,
                attack_category=attack_category,
                succeeded=False,
                finding_count=0,
                evidence_count=0,
                max_severity=None,
                failure_reason=failure_msg,
                duration_ms=duration_ms,
                request=request,
                decision_history=decision_history,
            )
            # Finalize only after intelligence has acted — injected nodes are now
            # in the graph and the loop will pick them up
            graph.try_complete()
            return

        duration_ms = int((time.monotonic() - t0) * 1000)

        if result.status == "failed":
            graph.mark_node_failed(
                node_id,
                failure_reason=result.failure_reason or "ValidationService failed",
                duration_ms=duration_ms,
            )
            self._adapt_from_node_result(
                graph=graph,
                node_id=node_id,
                attack_category=attack_category,
                succeeded=False,
                finding_count=0,
                evidence_count=len(result.evidence_ids),
                max_severity=None,
                failure_reason=result.failure_reason,
                duration_ms=duration_ms,
                request=request,
                decision_history=decision_history,
            )
            graph.try_complete()
            return

        # Accumulate global evidence/finding/risk lists
        all_finding_ids.extend(result.finding_ids)
        all_evidence_ids.extend(result.evidence_ids)
        risk_ids = [ri.incident_id for ri in result.risk_incidents]
        all_risk_incident_ids.extend(risk_ids)

        # Determine max severity found in this node
        max_severity = _max_severity_from_result(result)

        # mark_node_completed evaluates goal + budget. GoalAchievedSignal and
        # BudgetExhaustedError propagate out immediately — intelligence does NOT
        # run for these terminal paths (correct: campaign is already decided).
        # Natural completion is deferred: _check_completion() is NOT called
        # inside mark_node_completed any more — try_complete() below does it
        # AFTER intelligence has had a chance to inject new nodes.
        graph.mark_node_completed(
            node_id=node_id,
            evidence_ids=result.evidence_ids,
            finding_ids=result.finding_ids,
            risk_incident_ids=risk_ids,
            duration_ms=duration_ms,
            max_severity_found=max_severity,
        )

        # Intelligence runs here — graph is still RUNNING/not yet finalized.
        # Injected nodes become READY and the outer loop picks them up.
        self._adapt_from_node_result(
            graph=graph,
            node_id=node_id,
            attack_category=attack_category,
            succeeded=True,
            finding_count=len(result.finding_ids),
            evidence_count=len(result.evidence_ids),
            max_severity=max_severity,
            failure_reason=None,
            duration_ms=duration_ms,
            request=request,
            decision_history=decision_history,
            evaluation_feedback=getattr(result, "evaluation_feedback", None),
        )

        # Finalize: graph becomes COMPLETED only if all nodes are now terminal.
        # If intelligence injected new READY nodes, this is a no-op.
        graph.try_complete()

    def _adapt_from_node_result(
        self,
        graph: AttackGraph,
        node_id: str,
        attack_category: str,
        succeeded: bool,
        finding_count: int,
        evidence_count: int,
        max_severity: str | None,
        failure_reason: str | None,
        duration_ms: int,
        request: RedTeamRequest,
        decision_history: CampaignDecisionHistory,
        evaluation_feedback: object | None = None,
    ) -> None:
        """Consult the campaign intelligence service and act on its decision.

        This is synchronous (the intelligence service is sync) and non-fatal —
        any exception in the intelligence layer is logged and swallowed so the
        main execution loop is never disrupted by intelligence failures.
        """
        if self._campaign_intelligence is None:
            return

        try:
            all_results = graph.all_results()
            completed_summaries = tuple(
                NodeEvidenceSummary(
                    node_id=r.node_id,
                    attack_category=r.attack_category,
                    succeeded=r.state == AttackNodeState.COMPLETED,
                    finding_count=r.findings_count,
                    max_severity=r.max_severity_found,
                    failure_reason=r.failure_reason,
                    duration_ms=r.duration_ms,
                    evidence_count=len(r.evidence_ids),
                )
                for r in all_results
                if r.state.value in (
                    "completed", "failed", "blocked", "skipped"
                )
            )

            # Count consecutive failures
            consecutive_failures = 0
            consecutive_successes = 0
            for summary in reversed(completed_summaries):
                if summary.succeeded:
                    if consecutive_failures == 0:
                        consecutive_successes += 1
                    else:
                        break
                else:
                    if consecutive_successes == 0:
                        consecutive_failures += 1
                    else:
                        break

            eval_metadata: dict[str, str] = {}
            if evaluation_feedback is not None:
                from redforge.domain.red_team.eval_signals import (
                    EVAL_KEY_EVALUATION_QUALITY,
                    EVAL_KEY_RECOMMENDED_ACTION,
                    EVAL_KEY_REQUIRES_MORE_EVIDENCE,
                )
                recommended = getattr(evaluation_feedback, "recommended_campaign_action", None)
                if isinstance(recommended, str):
                    eval_metadata[EVAL_KEY_RECOMMENDED_ACTION] = recommended
                quality = getattr(evaluation_feedback, "evaluation_quality", None)
                if isinstance(quality, str):
                    eval_metadata[EVAL_KEY_EVALUATION_QUALITY] = quality
                requires_more = getattr(evaluation_feedback, "requires_more_evidence", None)
                if isinstance(requires_more, bool):
                    eval_metadata[EVAL_KEY_REQUIRES_MORE_EVIDENCE] = (
                        "true" if requires_more else "false"
                    )

            ctx = CampaignIntelligenceContext(
                organization_id=request.organization_id,
                target_provider=request.target_provider,
                attack_category=attack_category,
                node_id=node_id,
                node_summary=NodeEvidenceSummary(
                    node_id=node_id,
                    attack_category=attack_category,
                    succeeded=succeeded,
                    finding_count=finding_count,
                    max_severity=max_severity,
                    failure_reason=failure_reason,
                    duration_ms=duration_ms,
                    evidence_count=evidence_count,
                ),
                total_findings_so_far=graph.total_findings,
                total_nodes_executed=graph.nodes_executed,
                total_nodes_planned=len(all_results),
                consecutive_failures=consecutive_failures,
                consecutive_successes=consecutive_successes,
                completed_nodes=completed_summaries,
                prior_decisions=decision_history.all_records,
                goal=graph.goal,
                metadata=eval_metadata,
            )

            decision = self._campaign_intelligence.decide(ctx)
            # Stamp graph_id (orchestrator owns it, service doesn't)
            from dataclasses import replace
            decision = replace(decision, graph_id=graph.id)

            # Apply decision and capture which node IDs were actually admitted
            applied_node_ids, failure_reason = self._apply_decision(decision, graph)

            # Stamp applied metadata onto the immutable record before archiving
            decision = replace(
                decision,
                applied_node_ids=tuple(applied_node_ids),
                application_failure_reason=failure_reason,
            )
            decision_history.record(decision)

        except Exception as exc:
            logger.warning(
                "campaign_intelligence_error",
                graph_id=graph.id,
                node_id=node_id,
                error=str(exc),
            )

    def _apply_decision(
        self,
        decision: CampaignDecisionRecord,
        graph: AttackGraph,
    ) -> tuple[list[str], str | None]:
        """Apply a campaign decision to the running graph.

        Returns:
            (applied_node_ids, failure_reason) where applied_node_ids contains
            the node IDs ACTUALLY ADMITTED to the graph (not just recommended),
            and failure_reason is non-None if any injection was rejected.

        ESCALATE/BRANCH/PIVOT: attempt to inject recommended categories.
            Duplicates and terminal-graph rejections are recorded in failure_reason.
        STOP: cancel the graph (adaptive early termination).
        CONTINUE/RETRY_WITH_VARIANT: no structural change.
        """
        action = decision.action
        applied: list[str] = []
        failures: list[str] = []

        if action in (
            CampaignDecisionAction.ESCALATE,
            CampaignDecisionAction.BRANCH,
            CampaignDecisionAction.PIVOT,
        ):
            reason = action.value
            for cat in decision.injected_categories:
                if graph.is_terminal:
                    failures.append(f"{cat}:terminal")
                    continue
                existing_cats = {r.attack_category for r in graph.all_results()}
                if cat in existing_cats:
                    failures.append(f"{cat}:duplicate")
                    continue
                prefix = "pivot" if action == CampaignDecisionAction.PIVOT else "injected"
                new_node_id = f"{prefix}_{cat}_{decision.decision_id[:8]}"
                try:
                    graph.inject_node(
                        node_id=new_node_id,
                        attack_category=cat,
                        decision_id=decision.decision_id,
                        reason=reason,
                    )
                    applied.append(new_node_id)
                    logger.info(
                        "campaign_node_injected",
                        graph_id=graph.id,
                        node_id=new_node_id,
                        attack_category=cat,
                        reason=reason,
                    )
                except Exception as exc:
                    failures.append(f"{cat}:{exc}")
                    logger.warning(
                        "campaign_node_injection_failed",
                        graph_id=graph.id,
                        attack_category=cat,
                        error=str(exc),
                    )

        elif action == CampaignDecisionAction.STOP:
            if not graph.is_terminal:
                graph.cancel(
                    f"adaptive_stop: {decision.rationale[:100]}"
                )
                logger.info(
                    "campaign_adaptive_stop",
                    graph_id=graph.id,
                    rationale=decision.rationale[:100],
                    confidence=decision.confidence,
                )

        failure_reason = "; ".join(failures) if failures else None
        return applied, failure_reason

    # ── KG projection ─────────────────────────────────────────────────────────

    def _project_to_kg(
        self,
        graph: AttackGraph,
        request: RedTeamRequest,
        decision_history: CampaignDecisionHistory | None = None,
    ) -> None:
        """Project the completed AttackGraph into the KnowledgeGraph."""
        if self._knowledge_graph is None:
            return
        try:
            from redforge.application.knowledge_graph import (
                GraphEdge,
                GraphNode,
                NodeType,
                RelationshipType,
            )
            kg = self._knowledge_graph

            # Graph node
            kg.add_node(GraphNode(
                node_id=graph.id,
                node_type=NodeType.ATTACK_GRAPH,
                label=f"AttackGraph:{graph.id[:8]}",
                metadata={
                    "state": graph.state.value,
                    "goal_achieved": graph.goal_achieved,
                    "total_findings": graph.total_findings,
                },
            ))

            # Objective node
            objective = request.goal.objective
            obj_node_id = f"obj:{graph.id}"
            kg.add_node(GraphNode(
                node_id=obj_node_id,
                node_type=NodeType.ATTACK_OBJECTIVE,
                label=objective.name,
                metadata={
                    "goal_criteria": objective.goal_criteria.value,
                    "target_categories": sorted(objective.target_categories),
                },
            ))
            kg.add_edge(GraphEdge(
                source_id=graph.id,
                target_id=obj_node_id,
                relationship=RelationshipType.ATTACK_GRAPH_HAS_OBJECTIVE,
                label="has_objective",
            ))

            # Campaign link
            if request.campaign_id:
                kg.add_edge(GraphEdge(
                    source_id=request.campaign_id,
                    target_id=graph.id,
                    relationship=RelationshipType.CAMPAIGN_HAS_ATTACK_GRAPH,
                    label="has_attack_graph",
                ))

            # Per-node projections
            for result in graph.all_results():
                kg.add_node(GraphNode(
                    node_id=result.node_id,
                    node_type=NodeType.ATTACK_GRAPH_NODE,
                    label=f"{result.attack_category}:{result.node_id[:8]}",
                    metadata={
                        "state": result.state.value,
                        "attack_category": result.attack_category,
                        "findings_count": result.findings_count,
                    },
                ))
                kg.add_edge(GraphEdge(
                    source_id=graph.id,
                    target_id=result.node_id,
                    relationship=RelationshipType.ATTACK_GRAPH_HAS_NODE,
                    label="has_node",
                ))
                for fid in result.finding_ids:
                    kg.add_edge(GraphEdge(
                        source_id=result.node_id,
                        target_id=fid,
                        relationship=RelationshipType.ATTACK_NODE_PRODUCED,
                        label="produced_finding",
                    ))

            # Project decision nodes with honest applied vs recommended counts
            if decision_history:
                for record in decision_history.all_records:
                    decision_node_id = f"decision:{record.decision_id}"
                    kg.add_node(GraphNode(
                        node_id=decision_node_id,
                        node_type=NodeType.CAMPAIGN_DECISION,
                        label=f"Decision:{record.action.value}",
                        metadata={
                            "action": record.action.value,
                            "confidence": str(record.confidence),
                            "rationale": record.rationale[:120],
                            "triggering_node": record.triggering_node_id,
                            "recommended_count": str(len(record.injected_categories)),
                            "applied_count": str(len(record.applied_node_ids)),
                            "application_failure": record.application_failure_reason or "",
                        },
                    ))
                    kg.add_edge(GraphEdge(
                        source_id=record.triggering_node_id,
                        target_id=decision_node_id,
                        relationship=RelationshipType.DECISION_INFLUENCED_NODE,
                        label="triggered_decision",
                    ))

        except Exception as exc:
            logger.warning("red_team_kg_projection_failed", error=str(exc))

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_result_from_graph(
        self,
        graph: AttackGraph,
        request: RedTeamRequest,
        all_finding_ids: list[str],
        all_evidence_ids: list[str],
        all_risk_incident_ids: list[str],
        decision_history: CampaignDecisionHistory | None = None,
    ) -> RedTeamResult:
        results_by_state = {
            AttackNodeState.COMPLETED: 0,
            AttackNodeState.FAILED: 0,
            AttackNodeState.BLOCKED: 0,
            AttackNodeState.SKIPPED: 0,
        }
        node_summaries: list[RedTeamNodeSummary] = []
        total_duration_ms = 0
        for r in graph.all_results():
            if r.state in results_by_state:
                results_by_state[r.state] += 1
            total_duration_ms += r.duration_ms
            node_summaries.append(RedTeamNodeSummary(
                node_id=r.node_id,
                attack_category=r.attack_category,
                state=r.state.value,
                findings_count=r.findings_count,
                evidence_count=len(r.evidence_ids),
                duration_ms=r.duration_ms,
                failure_reason=r.failure_reason,
            ))
        dh = decision_history
        return RedTeamResult(
            graph_id=graph.id,
            campaign_id=request.campaign_id or graph.id,
            organization_id=request.organization_id,
            state=graph.state.value,
            goal_achieved=graph.goal_achieved,
            objective_name=request.goal.objective.name,
            total_nodes=len(graph.all_results()),
            nodes_executed=graph.nodes_executed,
            completed_nodes=results_by_state[AttackNodeState.COMPLETED],
            failed_nodes=results_by_state[AttackNodeState.FAILED],
            blocked_nodes=results_by_state[AttackNodeState.BLOCKED],
            skipped_nodes=results_by_state[AttackNodeState.SKIPPED],
            total_findings=graph.total_findings,
            total_evidence=len(all_evidence_ids),
            all_finding_ids=all_finding_ids,
            all_evidence_ids=all_evidence_ids,
            all_risk_incident_ids=all_risk_incident_ids,
            duration_ms=total_duration_ms,
            node_summaries=node_summaries,
            decision_history=list(dh.all_records) if dh else [],
            intelligence_confidence=dh.average_confidence if dh else 0.0,
            injected_nodes=dh.total_injections if dh else 0,
        )


def _max_severity_from_result(result: ValidationServiceResult) -> str | None:
    """Extract the highest severity finding from a ValidationServiceResult."""
    best: str | None = None
    best_rank = -1
    for ri in result.risk_incidents:
        sev = str(ri.priority.value) if hasattr(ri.priority, "value") else str(ri.priority)
        rank = _SEVERITY_RANK.get(sev.lower(), -1)
        if rank > best_rank:
            best_rank = rank
            best = sev.lower()
    return best
