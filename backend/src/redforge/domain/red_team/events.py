"""Domain events for the Red Team bounded context — Sprint 34/35."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class RedTeamEvent:
    """Base for all red team domain events."""

    campaign_id: str
    graph_id: str
    organization_id: str
    occurred_at: datetime = field(default_factory=_utc_now)


@dataclass(frozen=True)
class AttackGraphCreated(RedTeamEvent):
    """Raised when an AttackGraph is initialized from a CampaignGoal."""

    node_count: int = 0
    objective_name: str = ""
    attack_categories: tuple[str, ...] = ()


@dataclass(frozen=True)
class AttackNodeReady(RedTeamEvent):
    """Raised when a node transitions from PENDING to READY."""

    node_id: str = ""
    attack_category: str = ""


@dataclass(frozen=True)
class AttackNodeStarted(RedTeamEvent):
    """Raised when a node begins execution (READY → RUNNING)."""

    node_id: str = ""
    attack_category: str = ""


@dataclass(frozen=True)
class AttackNodeCompleted(RedTeamEvent):
    """Raised when a node finishes execution with findings."""

    node_id: str = ""
    attack_category: str = ""
    findings_count: int = 0
    evidence_count: int = 0
    duration_ms: int = 0


@dataclass(frozen=True)
class AttackNodeFailed(RedTeamEvent):
    """Raised when a node's execution fails."""

    node_id: str = ""
    attack_category: str = ""
    failure_reason: str = ""


@dataclass(frozen=True)
class AttackNodeBlocked(RedTeamEvent):
    """Raised when a node is blocked because a required dependency failed."""

    node_id: str = ""
    blocking_node_id: str = ""


@dataclass(frozen=True)
class AttackNodeSkipped(RedTeamEvent):
    """Raised when a node is skipped due to conditional edge evaluation."""

    node_id: str = ""
    attack_category: str = ""
    reason: str = ""


@dataclass(frozen=True)
class GoalAchieved(RedTeamEvent):
    """Raised when the AttackObjective's goal_criteria is satisfied."""

    objective_name: str = ""
    achieved_by_node_id: str = ""
    total_findings: int = 0
    total_nodes_executed: int = 0


@dataclass(frozen=True)
class BudgetExhausted(RedTeamEvent):
    """Raised when a BudgetConstraint limit is reached before goal achieved."""

    limit_type: str = ""    # "max_nodes" | "max_duration_s" | "max_findings"
    limit_value: int = 0
    nodes_executed: int = 0


@dataclass(frozen=True)
class AttackGraphPaused(RedTeamEvent):
    """Raised when the graph execution is paused."""

    pending_nodes: int = 0


@dataclass(frozen=True)
class AttackGraphResumed(RedTeamEvent):
    """Raised when the graph execution is resumed after a pause."""


@dataclass(frozen=True)
class AttackGraphCancelled(RedTeamEvent):
    """Raised when the graph execution is explicitly cancelled."""

    reason: str = ""


@dataclass(frozen=True)
class AttackGraphCompleted(RedTeamEvent):
    """Raised when ALL nodes reach terminal states (regardless of goal)."""

    total_nodes: int = 0
    completed_nodes: int = 0
    failed_nodes: int = 0
    blocked_nodes: int = 0
    skipped_nodes: int = 0
    goal_achieved: bool = False
    total_findings: int = 0
    duration_ms: int = 0


@dataclass(frozen=True)
class AttackNodeInjected(RedTeamEvent):
    """Raised when the adaptive intelligence layer injects a new node at runtime.

    Injected nodes are leaf nodes with no dependencies — they are immediately
    READY for execution. The triggering_decision_id links this event to the
    CampaignDecisionRecord that caused the injection.
    """

    node_id: str = ""
    attack_category: str = ""
    triggering_decision_id: str = ""
    injection_reason: str = ""   # "escalate" | "branch" | "pivot"
