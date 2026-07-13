"""Adaptive Campaign Intelligence Service — Sprint 36/37.

Architecture:
- Sits at the APPLICATION layer inside the red_team bounded context.
- Receives a CampaignIntelligenceContext after each node completes and
  returns a CampaignDecisionRecord that the orchestrator acts upon.
- Does NOT access the database, call LLMs, or publish events — all I/O
  belongs to the orchestrator that calls this service.
- Default implementation is rule-based (deterministic, testable).
- Customers can replace it by implementing CampaignIntelligenceServicePort.

Decision logic:
  Node succeeded with CRITICAL/HIGH finding → ESCALATE
  Node succeeded with MEDIUM/LOW finding    → BRANCH
  Node failed (provider/network error)      → PIVOT
  Node failed (execution error, < threshold) → RETRY_WITH_VARIANT
  > MAX_CONSECUTIVE_FAILURES consecutive    → STOP (low confidence)
  Goal already achieved                     → STOP
  Otherwise                                 → CONTINUE

Escalation/Branch maps encode which attack categories are natural
follow-ons for a given category. These are application-layer knowledge
(not domain knowledge) and can be overridden by injecting a custom
EscalationMapPort.
"""

from __future__ import annotations

import contextlib
import uuid
from typing import Protocol, runtime_checkable

from redforge.application.runtime.evaluation.consensus import EvaluatorConsensus
from redforge.core.logging import get_logger
from redforge.domain.red_team.campaign_decision import (
    CampaignDecisionAction,
    CampaignDecisionRecord,
    CampaignIntelligenceContext,
    NodeEvidenceSummary,
)

logger = get_logger(__name__)

# Stop campaign if this many nodes in a row have failed
_MAX_CONSECUTIVE_FAILURES = 3

# Severity ranks for comparison (same ordering as in entity.py and orchestrator.py)
_SEVERITY_RANK: dict[str, int] = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0,
}

# Which categories to inject when a node succeeds with high severity
# Key: attack category that succeeded; Value: escalation follow-ons
_ESCALATION_MAP: dict[str, tuple[str, ...]] = {
    "prompt_injection": ("indirect_prompt_injection", "multi_modal_prompt_injection"),
    "indirect_prompt_injection": ("agent_chain_injection", "rag_poisoning"),
    "jailbreak": ("role_play_jailbreak", "many_shot_jailbreak"),
    "role_play_jailbreak": ("persona_theft", "authority_escalation_jailbreak"),
    "data_exfiltration": ("system_prompt_extraction", "training_data_extraction"),
    "system_prompt_extraction": ("configuration_leakage", "secret_extraction"),
    "tool_misuse": ("tool_chain_abuse", "mcp_tool_injection"),
    "mcp_tool_injection": ("mcp_resource_hijack", "mcp_server_bypass"),
    "agent_hijacking": ("cross_agent_injection", "agent_chain_injection"),
    "rag_poisoning": ("vector_store_poisoning", "retrieval_manipulation"),
    "cross_context_injection": ("session_confusion", "tenant_boundary_violation"),
    "model_denial_of_service": ("resource_exhaustion", "prompt_flooding"),
}

# Which categories to inject when a node succeeds with medium/low severity
# Key: attack category; Value: sibling categories to branch into
_BRANCH_MAP: dict[str, tuple[str, ...]] = {
    "prompt_injection": ("jailbreak", "system_prompt_extraction"),
    "jailbreak": ("prompt_injection", "role_play_jailbreak"),
    "data_exfiltration": ("system_prompt_extraction", "configuration_leakage"),
    "tool_misuse": ("agent_hijacking", "mcp_tool_injection"),
    "mcp_tool_injection": ("tool_misuse", "tool_chain_abuse"),
    "agent_hijacking": ("cross_agent_injection", "tool_misuse"),
    "rag_poisoning": ("indirect_prompt_injection", "vector_store_poisoning"),
    "cross_context_injection": ("tenant_boundary_violation", "session_confusion"),
    "model_denial_of_service": ("resource_exhaustion", "prompt_flooding"),
    "indirect_prompt_injection": ("rag_poisoning", "agent_chain_injection"),
}

# Alternative attack categories to pivot to when a node is blocked
_PIVOT_MAP: dict[str, tuple[str, ...]] = {
    "prompt_injection": ("indirect_prompt_injection", "jailbreak"),
    "jailbreak": ("role_play_jailbreak", "authority_escalation_jailbreak"),
    "data_exfiltration": ("system_prompt_extraction", "side_channel_attacks"),
    "tool_misuse": ("tool_chain_abuse", "mcp_tool_injection"),
    "agent_hijacking": ("cross_agent_injection", "indirect_prompt_injection"),
    "rag_poisoning": ("vector_store_poisoning", "indirect_prompt_injection"),
}

# Provider-specific payload hint (which mutation strategy to prefer)
_PROVIDER_PAYLOAD_HINTS: dict[str, str] = {
    "openai": "unicode",
    "anthropic": "zero_width",
    "azure_openai": "base64",
    "local": "markdown",
    "bedrock": "html",
    "vertex": "typoglycemia",
}


# ─── Protocol ─────────────────────────────────────────────────────────────────


@runtime_checkable
class CampaignIntelligenceServicePort(Protocol):
    """Adaptive decision engine for campaign execution.

    Called after each node completes. Returns a CampaignDecisionRecord
    describing what the campaign should do next.

    Implementations must be stateless — all context is in
    CampaignIntelligenceContext. Stateful learning (cross-campaign) is
    out of scope for this protocol; inject a stateful implementation if
    needed.
    """

    def decide(
        self,
        context: CampaignIntelligenceContext,
    ) -> CampaignDecisionRecord:
        """Return the decision for the next campaign step."""
        ...


# ─── Confidence Estimator ─────────────────────────────────────────────────────


class ConfidenceEstimator:
    """Estimates confidence in a campaign decision.

    Higher confidence when:
    - Node succeeded with high-severity findings.
    - Prior decisions in this campaign have been consistent.
    - The attack category is well-known (has escalation/branch maps).

    Lower confidence when:
    - Many consecutive failures.
    - Node failed with unexpected errors.
    - No prior evidence to calibrate from.
    """

    def estimate(
        self,
        context: CampaignIntelligenceContext,
        action: CampaignDecisionAction,
    ) -> float:
        """Return confidence in [0.0, 1.0]."""
        base = 0.5

        summary = context.node_summary

        if action == CampaignDecisionAction.CONTINUE:
            # High confidence in CONTINUE: the node completed as expected
            base = 0.75
            if summary.succeeded and summary.produced_findings:
                base = 0.85

        elif action in (
            CampaignDecisionAction.ESCALATE,
            CampaignDecisionAction.BRANCH,
        ):
            # Confidence proportional to finding quality
            if summary.is_high_confidence_success:
                base = 0.90
            elif summary.is_partial_success:
                base = 0.70
            else:
                base = 0.55

        elif action == CampaignDecisionAction.PIVOT:
            # Lower confidence — we're guessing a pivot will help
            base = 0.55

        elif action == CampaignDecisionAction.RETRY_WITH_VARIANT:
            # Medium confidence — variant might work
            base = 0.60
            if context.consecutive_failures >= 2:
                base = 0.45

        elif action == CampaignDecisionAction.STOP:
            base = 0.85 if context.consecutive_failures >= _MAX_CONSECUTIVE_FAILURES else 0.70

        # Reduce confidence if many failures in history
        failure_penalty = min(context.consecutive_failures * 0.05, 0.25)
        return max(0.0, min(1.0, base - failure_penalty))


# ─── Campaign Learning ────────────────────────────────────────────────────────


class CampaignLearner:
    """Derives patterns from completed node evidence within a campaign.

    Stateless per-call. Called by RuleBasedCampaignIntelligenceService to
    enrich context before making decisions.

    Patterns extracted:
    - Which categories have succeeded (for escalation candidate filtering)
    - Which categories have failed (to avoid re-suggesting them)
    - Dominant severity (to calibrate escalation aggressiveness)
    """

    def categories_with_findings(
        self, completed: tuple[NodeEvidenceSummary, ...]
    ) -> frozenset[str]:
        """Return the set of attack categories that produced findings."""
        return frozenset(
            n.attack_category for n in completed
            if n.produced_findings
        )

    def categories_that_failed(
        self, completed: tuple[NodeEvidenceSummary, ...]
    ) -> frozenset[str]:
        """Return categories that failed (not just produced no findings)."""
        return frozenset(
            n.attack_category for n in completed
            if n.is_execution_failure
        )

    def categories_already_run(
        self, completed: tuple[NodeEvidenceSummary, ...]
    ) -> frozenset[str]:
        """Return all categories that have been executed (any outcome)."""
        return frozenset(n.attack_category for n in completed)

    def dominant_severity(
        self, completed: tuple[NodeEvidenceSummary, ...]
    ) -> str | None:
        """Return the highest severity seen across all completed nodes."""
        best: str | None = None
        best_rank = -1
        for node in completed:
            if node.max_severity is not None:
                rank = _SEVERITY_RANK.get(node.max_severity, -1)
                if rank > best_rank:
                    best_rank = rank
                    best = node.max_severity
        return best


# ─── Default Implementation ───────────────────────────────────────────────────


class RuleBasedCampaignIntelligenceService:
    """Default deterministic campaign intelligence implementation.

    All decisions are rule-based — no LLM calls, no external I/O.
    Rules are described in the module docstring and encoded as pure
    conditionals. Customers who need ML-driven intelligence can inject
    a custom CampaignIntelligenceServicePort implementation.

    Injection points:
    - confidence_estimator: override confidence scoring logic
    - campaign_learner: override pattern extraction
    - escalation_map: override which categories escalate to
    - branch_map: override which categories branch to
    - pivot_map: override which categories to pivot to
    """

    def __init__(
        self,
        confidence_estimator: ConfidenceEstimator | None = None,
        campaign_learner: CampaignLearner | None = None,
        escalation_map: dict[str, tuple[str, ...]] | None = None,
        branch_map: dict[str, tuple[str, ...]] | None = None,
        pivot_map: dict[str, tuple[str, ...]] | None = None,
        provider_payload_hints: dict[str, str] | None = None,
        max_consecutive_failures: int = _MAX_CONSECUTIVE_FAILURES,
    ) -> None:
        self._confidence = confidence_estimator or ConfidenceEstimator()
        self._learner = campaign_learner or CampaignLearner()
        self._escalation_map = escalation_map or _ESCALATION_MAP
        self._branch_map = branch_map or _BRANCH_MAP
        self._pivot_map = pivot_map or _PIVOT_MAP
        self._provider_hints = provider_payload_hints or _PROVIDER_PAYLOAD_HINTS
        self._max_failures = max_consecutive_failures

    def decide(
        self,
        context: CampaignIntelligenceContext,
    ) -> CampaignDecisionRecord:
        """Apply rule-based logic and return the campaign decision."""
        summary = context.node_summary
        action, rationale, injected, alt_strategy, payload_hint = self._evaluate(context, summary)
        # Modulate action based on evaluation quality signals in context.metadata.
        # This consumes eval_consensus_state, eval_evaluator_uncertainty, and
        # eval_recommended_action injected by the orchestrator after evaluation.
        # Recommendation != applied action: signals inform modulation, not replace decide().
        action, rationale = _modulate_from_eval_signals(action, rationale, context.metadata)
        confidence = self._confidence.estimate(context, action)

        record = CampaignDecisionRecord(
            decision_id=str(uuid.uuid4()),
            graph_id="",  # set by orchestrator after creation
            organization_id=context.organization_id,
            triggering_node_id=context.node_id,
            triggering_attack_category=context.attack_category,
            action=action,
            rationale=rationale,
            confidence=confidence,
            injected_categories=injected,
            alternative_strategy=alt_strategy,
            payload_hint=payload_hint,
        )

        logger.info(
            "campaign_decision",
            organization_id=context.organization_id,
            node_id=context.node_id,
            attack_category=context.attack_category,
            action=action.value,
            confidence=confidence,
            injected_categories=list(injected),
        )
        return record

    # ── Decision evaluation ──────────────────────────────────────────────────

    def _evaluate(
        self,
        context: CampaignIntelligenceContext,
        summary: NodeEvidenceSummary,
    ) -> tuple[
        CampaignDecisionAction,
        str,
        tuple[str, ...],
        str | None,
        str | None,
    ]:
        """Return (action, rationale, injected_categories, alt_strategy, payload_hint)."""
        already_run = self._learner.categories_already_run(context.completed_nodes)

        # STOP: too many consecutive failures — low confidence further attempts help
        if context.consecutive_failures >= self._max_failures:
            return (
                CampaignDecisionAction.STOP,
                f"Stopping after {context.consecutive_failures} consecutive failures — "
                f"low confidence that further attempts will succeed.",
                (),
                None,
                None,
            )

        # If node succeeded with HIGH/CRITICAL → ESCALATE
        if summary.is_high_confidence_success:
            candidates = self._escalation_map.get(context.attack_category, ())
            new_cats = tuple(c for c in candidates if c not in already_run)
            if new_cats:
                return (
                    CampaignDecisionAction.ESCALATE,
                    f"Node produced {summary.max_severity} finding in "
                    f"'{context.attack_category}'. Escalating to: {list(new_cats)}.",
                    new_cats,
                    None,
                    self._provider_hint(context.target_provider),
                )
            # No new escalation targets available — CONTINUE
            return (
                CampaignDecisionAction.CONTINUE,
                f"High-severity finding in '{context.attack_category}' but all "
                f"escalation targets already executed.",
                (),
                None,
                None,
            )

        # If node succeeded with MEDIUM/LOW → BRANCH
        if summary.is_partial_success:
            candidates = self._branch_map.get(context.attack_category, ())
            new_cats = tuple(c for c in candidates if c not in already_run)
            if new_cats:
                return (
                    CampaignDecisionAction.BRANCH,
                    f"Node produced {summary.max_severity} finding in "
                    f"'{context.attack_category}'. Branching to: {list(new_cats)}.",
                    new_cats,
                    None,
                    None,
                )

        # If node succeeded but no findings → CONTINUE
        if summary.succeeded and not summary.produced_findings:
            return (
                CampaignDecisionAction.CONTINUE,
                f"Node '{context.attack_category}' succeeded but produced no findings. "
                f"Continuing to next planned node.",
                (),
                None,
                None,
            )

        # If node failed with execution error and not over retry threshold → RETRY_WITH_VARIANT
        if summary.is_execution_failure and context.consecutive_failures < 2:
            hint = self._provider_hint(context.target_provider)
            alt = self._pick_pivot(context.attack_category, already_run)
            return (
                CampaignDecisionAction.RETRY_WITH_VARIANT,
                f"Node '{context.attack_category}' failed with execution error: "
                f"'{summary.failure_reason}'. Retrying with payload variant.",
                (),
                alt,
                hint,
            )

        # If node failed → PIVOT
        if not summary.succeeded:
            alt = self._pick_pivot(context.attack_category, already_run)
            if alt:
                return (
                    CampaignDecisionAction.PIVOT,
                    f"Node '{context.attack_category}' was blocked/failed. "
                    f"Pivoting to '{alt}'.",
                    (alt,),
                    alt,
                    self._provider_hint(context.target_provider),
                )
            return (
                CampaignDecisionAction.CONTINUE,
                f"Node '{context.attack_category}' failed but no pivot available. "
                f"Continuing with remaining planned nodes.",
                (),
                None,
                None,
            )

        # Default: CONTINUE
        return (
            CampaignDecisionAction.CONTINUE,
            f"Node '{context.attack_category}' completed normally. "
            f"Continuing to next planned node.",
            (),
            None,
            None,
        )

    def _provider_hint(self, provider: str) -> str | None:
        return self._provider_hints.get(provider.lower())

    def _pick_pivot(
        self, attack_category: str, already_run: frozenset[str]
    ) -> str | None:
        candidates = self._pivot_map.get(attack_category, ())
        for candidate in candidates:
            if candidate not in already_run:
                return candidate
        return None


# ─── Evaluation Quality Modulation ───────────────────────────────────────────


def _modulate_from_eval_signals(
    action: CampaignDecisionAction,
    rationale: str,
    metadata: dict[str, str],
) -> tuple[CampaignDecisionAction, str]:
    """Modulate campaign action based on evaluation quality signals.

    Uses parse_eval_signals() for strict, centralized, fail-closed parsing of
    the dict[str, str] metadata transport (see domain/red_team/eval_signals.py).
    No magic string keys appear here — all key constants are imported from there.

    The modulation NEVER blindly copies the recommended action from metadata —
    it uses the signals as evidence to adjust the rule-based decision.
    Recommendation != applied action invariant is preserved.
    """
    from redforge.domain.red_team.eval_signals import EvalQuality, parse_eval_signals

    if not metadata:
        return action, rationale

    signals = parse_eval_signals(metadata)

    # Parse consensus state (fail-closed on unknown values)
    consensus_state: EvaluatorConsensus | None = None
    if signals.consensus_state:
        with contextlib.suppress(ValueError):
            consensus_state = EvaluatorConsensus(signals.consensus_state)

    # Parse recommended action (advisory signal only)
    recommended_action: CampaignDecisionAction | None = None
    if signals.recommended_action:
        with contextlib.suppress(ValueError):
            recommended_action = CampaignDecisionAction(signals.recommended_action)

    # Rule 1: Adapter requires more evidence — critical safety gate.
    # Do not escalate when the evaluation pipeline lacks sufficient signal to
    # trust the apparent finding severity. Downgrade to retry for cleaner evidence.
    if (
        signals.requires_more_evidence
        and action in (CampaignDecisionAction.ESCALATE, CampaignDecisionAction.BRANCH)
    ):
        return (
            CampaignDecisionAction.RETRY_WITH_VARIANT,
            f"{rationale} [eval_modulation: evaluation pipeline requires more evidence; "
            f"deferring escalation until signal quality improves]",
        )

    # Rule 2: Low evaluation quality — downgrade ESCALATE to BRANCH.
    # A low-quality evaluation (weak evaluators, insufficient evidence) should
    # not drive aggressive campaign escalation.
    if signals.evaluation_quality == EvalQuality.LOW and action == CampaignDecisionAction.ESCALATE:
        return (
            CampaignDecisionAction.BRANCH,
            f"{rationale} [eval_modulation: low evaluation quality; "
            f"branching instead of escalating for additional signal]",
        )

    # Rule 3: CONFLICTED consensus — evaluators disagree; retry for clearer signal.
    if (
        consensus_state == EvaluatorConsensus.CONFLICTED
        and action == CampaignDecisionAction.ESCALATE
    ):
        return (
            CampaignDecisionAction.RETRY_WITH_VARIANT,
            f"{rationale} [eval_modulation: evaluators conflicted; "
            f"retrying for unambiguous signal before escalating]",
        )

    # Rule 4: INSUFFICIENT_EVIDENCE — not enough signal to act on; gather more.
    if (
        consensus_state == EvaluatorConsensus.INSUFFICIENT_EVIDENCE
        and action in (CampaignDecisionAction.ESCALATE, CampaignDecisionAction.BRANCH)
    ):
        return (
            CampaignDecisionAction.RETRY_WITH_VARIANT,
            f"{rationale} [eval_modulation: insufficient evaluator evidence; "
            f"gathering more signal before committing to escalation]",
        )

    # Rule 5: PARTIAL_AGREEMENT — not all evaluators agree; downgrade ESCALATE to BRANCH.
    if (
        consensus_state == EvaluatorConsensus.PARTIAL_AGREEMENT
        and action == CampaignDecisionAction.ESCALATE
    ):
        return (
            CampaignDecisionAction.BRANCH,
            f"{rationale} [eval_modulation: partial evaluator agreement; "
            f"branching instead of escalating to avoid premature commitment]",
        )

    # Rule 6: Advisory — if adapter recommends a more conservative action than ESCALATE,
    # defer to the recommendation. This handles cases where the adapter detected quality
    # signals not captured by the rules above. Recommendation != applied action: we still
    # apply our own judgment (e.g., we won't downgrade CONTINUE or STOP actions).
    if (
        recommended_action is not None
        and action == CampaignDecisionAction.ESCALATE
        and recommended_action in (
            CampaignDecisionAction.RETRY_WITH_VARIANT,
            CampaignDecisionAction.PIVOT,
        )
    ):
        return (
            recommended_action,
            f"{rationale} [eval_modulation: adapter recommends {recommended_action.value} "
            f"over escalation based on evaluation quality signals]",
        )

    return action, rationale


# ─── Decision History ─────────────────────────────────────────────────────────


class CampaignDecisionHistory:
    """Collects and queries all adaptive decisions made during a campaign.

    Created fresh for each RedTeamOrchestrator.execute() call. Not persisted
    — the history is included in RedTeamResult for the caller to persist.
    """

    def __init__(self) -> None:
        self._records: list[CampaignDecisionRecord] = []

    def record(self, decision: CampaignDecisionRecord) -> None:
        self._records.append(decision)

    @property
    def all_records(self) -> tuple[CampaignDecisionRecord, ...]:
        return tuple(self._records)

    @property
    def total_decisions(self) -> int:
        return len(self._records)

    def decisions_for_action(
        self, action: CampaignDecisionAction
    ) -> tuple[CampaignDecisionRecord, ...]:
        return tuple(r for r in self._records if r.action == action)

    @property
    def total_injections(self) -> int:
        """Count nodes ACTUALLY ADMITTED to the graph (applied_node_ids).

        This is distinct from the total count of recommended injected_categories.
        A recommendation may be rejected because the graph was terminal,
        because the category was already present, or due to a domain error.
        """
        return sum(len(r.applied_node_ids) for r in self._records)

    @property
    def average_confidence(self) -> float:
        if not self._records:
            return 0.0
        return sum(r.confidence for r in self._records) / len(self._records)
