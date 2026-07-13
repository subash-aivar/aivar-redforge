"""Campaign decision value objects for the Adaptive Intelligence Layer.

These are pure domain value objects — no infrastructure imports.
They represent the outputs of the CampaignIntelligenceService and form
the audit trail of every adaptive decision taken during a campaign.

Separation of concerns:
- CampaignDecisionAction: what the intelligence engine decided to do
- NodeEvidenceSummary: compact per-node evidence snapshot (input)
- CampaignIntelligenceContext: full context presented to the intelligence service
- CampaignDecisionRecord: immutable audit record of one decision
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, unique
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.domain.red_team.value_objects import CampaignGoal


@unique
class CampaignDecisionAction(StrEnum):
    """What the adaptive intelligence engine decided to do after a node.

    Forward-only adaptive actions:
    - CONTINUE: proceed to next planned node without modification.
    - ESCALATE: node produced high-severity finding; inject more severe
        follow-up attack categories (escalation path).
    - BRANCH: node produced partial success; inject sibling attack
        categories to explore the same vector more broadly.
    - PIVOT: node was blocked or provider-rejected; switch to an
        alternative attack approach.
    - RETRY_WITH_VARIANT: node failed with execution error; retry with
        a different payload mutation strategy.
    - STOP: confidence is too low or goal already achieved; terminate
        the campaign early.
    """

    CONTINUE = "continue"
    ESCALATE = "escalate"
    BRANCH = "branch"
    PIVOT = "pivot"
    RETRY_WITH_VARIANT = "retry_with_variant"
    STOP = "stop"


@dataclass(frozen=True)
class NodeEvidenceSummary:
    """Compact, immutable view of what a single node produced.

    This is what the intelligence service sees — not the full
    ValidationServiceResult (which lives at the application layer).

    Attributes:
        node_id: The node identifier.
        attack_category: The category executed.
        succeeded: True if the node reached COMPLETED state.
        finding_count: Number of findings produced.
        max_severity: Highest severity found (None if none).
        failure_reason: Why the node failed (None if succeeded).
        duration_ms: Wall-clock execution time in milliseconds.
        evidence_count: Number of evidence records captured.
    """

    node_id: str
    attack_category: str
    succeeded: bool
    finding_count: int = 0
    max_severity: str | None = None
    failure_reason: str | None = None
    duration_ms: int = 0
    evidence_count: int = 0

    @property
    def produced_findings(self) -> bool:
        return self.finding_count > 0

    @property
    def is_high_confidence_success(self) -> bool:
        return self.succeeded and self.max_severity in ("critical", "high")

    @property
    def is_partial_success(self) -> bool:
        return self.succeeded and self.max_severity in ("medium", "low")

    @property
    def is_execution_failure(self) -> bool:
        """Provider/network failure (not a security pass — actual error)."""
        return not self.succeeded and self.failure_reason is not None


@dataclass(frozen=True)
class CampaignIntelligenceContext:
    """Everything the intelligence service needs to make its decision.

    Constructed by the orchestrator after each node completes; passed to
    CampaignIntelligenceServicePort.decide(). This is the canonical input
    boundary for the intelligence layer.

    All completed_nodes is the full history up to (and including) the
    node that just finished. The just-completed node is the last entry
    in completed_nodes.
    """

    organization_id: str
    target_provider: str
    attack_category: str          # the category that just completed
    node_id: str                  # the node that just completed
    node_summary: NodeEvidenceSummary
    total_findings_so_far: int
    total_nodes_executed: int
    total_nodes_planned: int
    consecutive_failures: int     # count of back-to-back failures
    consecutive_successes: int    # count of back-to-back successes
    completed_nodes: tuple[NodeEvidenceSummary, ...]  # all completed so far
    prior_decisions: tuple[CampaignDecisionRecord, ...]  # decisions this campaign
    goal: CampaignGoal | None = None
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CampaignDecisionRecord:
    """Immutable audit record of a single adaptive decision.

    Every decision made during a campaign is recorded here — this forms
    the `decision_history` on RedTeamResult for auditability and learning.
    """

    decision_id: str
    graph_id: str
    organization_id: str
    triggering_node_id: str
    triggering_attack_category: str
    action: CampaignDecisionAction
    rationale: str
    confidence: float                           # 0.0 - 1.0
    injected_categories: tuple[str, ...]        # categories RECOMMENDED by intelligence
    alternative_strategy: str | None            # for PIVOT
    payload_hint: str | None                    # for RETRY_WITH_VARIANT
    # Stamped by orchestrator after applying the decision:
    applied_node_ids: tuple[str, ...] = ()     # node IDs actually admitted to graph
    application_failure_reason: str | None = None  # non-None if any injection failed
    decided_at: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"CampaignDecisionRecord.confidence must be 0.0-1.0, got {self.confidence}"
            )
