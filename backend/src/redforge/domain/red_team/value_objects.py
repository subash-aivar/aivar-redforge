"""Value objects for the Red Team bounded context — Sprint 34/35."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, unique


@unique
class AttackNodeState(StrEnum):
    """Lifecycle state of a single node in an AttackGraph.

    Forward-only transitions (no backward movement):
      PENDING → READY → RUNNING → COMPLETED
                                 → FAILED
               → BLOCKED          (a dependency failed — terminal)
               → SKIPPED          (conditional edge not satisfied — terminal)
    """

    PENDING = "pending"
    READY = "ready"        # all dependencies satisfied; eligible for execution
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"    # at least one required dependency failed
    SKIPPED = "skipped"    # conditional edge evaluated to false


@unique
class AttackGraphState(StrEnum):
    """Overall state of an AttackGraph execution."""

    RUNNING = "running"
    PAUSED = "paused"
    GOAL_ACHIEVED = "goal_achieved"
    COMPLETED = "completed"    # all nodes reached terminal state, goal not achieved
    FAILED = "failed"          # failure threshold exceeded
    CANCELLED = "cancelled"


@unique
class GoalCriteria(StrEnum):
    """Defines when the red team campaign's goal is considered achieved.

    - FIRST_FINDING: stop as soon as any finding is produced.
    - SEVERITY_THRESHOLD: stop when a finding at or above severity_threshold found.
    - FINDING_COUNT: stop when total finding count reaches finding_count_threshold.
    - COVERAGE_THRESHOLD: stop when coverage_threshold_pct of categories completed.
    - ALL_COMPLETE: run all nodes regardless of findings (default exhaustive mode).
    """

    FIRST_FINDING = "first_finding"
    SEVERITY_THRESHOLD = "severity_threshold"
    FINDING_COUNT = "finding_count"
    COVERAGE_THRESHOLD = "coverage_threshold"
    ALL_COMPLETE = "all_complete"


@unique
class EdgeCondition(StrEnum):
    """Condition under which a dependency edge is satisfied.

    - ON_SUCCESS: successor runs only if predecessor completed successfully.
    - ON_FAILURE: successor runs only if predecessor failed.
    - ALWAYS: successor always runs after predecessor reaches any terminal state.
    """

    ON_SUCCESS = "on_success"
    ON_FAILURE = "on_failure"
    ALWAYS = "always"


@dataclass(frozen=True)
class AttackObjective:
    """What the red team is trying to achieve.

    Specifies the attack focus (categories) and the success criteria.
    An AttackObjective is immutable — once defined it does not change
    during the campaign run. Variations require a new campaign.
    """

    name: str
    description: str
    target_categories: frozenset[str]
    goal_criteria: GoalCriteria = GoalCriteria.ALL_COMPLETE
    severity_threshold: str = "high"       # used with SEVERITY_THRESHOLD
    finding_count_threshold: int = 1       # used with FINDING_COUNT
    coverage_threshold_pct: float = 80.0   # used with COVERAGE_THRESHOLD

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("AttackObjective.name must not be empty")
        if not self.target_categories:
            raise ValueError("AttackObjective.target_categories must not be empty")
        if not (0.0 < self.coverage_threshold_pct <= 100.0):
            raise ValueError("coverage_threshold_pct must be in (0, 100]")
        if self.finding_count_threshold < 1:
            raise ValueError("finding_count_threshold must be >= 1")


@dataclass(frozen=True)
class BudgetConstraint:
    """Resource limits for a red team campaign.

    Any non-None limit triggers early termination when exceeded.
    """

    max_nodes: int | None = None           # stop after executing this many nodes
    max_duration_s: int | None = None      # wall-clock time limit in seconds
    max_findings: int | None = None        # stop when this many findings accumulate


@dataclass(frozen=True)
class CampaignGoal:
    """Complete goal specification: objective + budget."""

    objective: AttackObjective
    budget: BudgetConstraint = field(default_factory=BudgetConstraint)


@dataclass(frozen=True)
class AttackEdge:
    """Directed dependency edge in an AttackGraph.

    An edge (from_node_id → to_node_id) means to_node_id depends on
    from_node_id. The successor (to_node_id) is READY only when
    from_node_id has reached a terminal state satisfying the condition.
    """

    from_node_id: str
    to_node_id: str
    condition: EdgeCondition = EdgeCondition.ON_SUCCESS

    def __post_init__(self) -> None:
        if self.from_node_id == self.to_node_id:
            raise ValueError("AttackEdge cannot be self-referencing")


@dataclass
class AttackNodeResult:
    """Accumulated execution result for a single AttackGraph node.

    Mutated in-place as evidence and findings are collected during
    the node's execution. Sealed when node reaches a terminal state.
    """

    node_id: str
    attack_category: str
    state: AttackNodeState = AttackNodeState.PENDING
    evidence_ids: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    risk_incident_ids: list[str] = field(default_factory=list)
    duration_ms: int = 0
    failure_reason: str | None = None
    findings_count: int = 0
    max_severity_found: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.state == AttackNodeState.COMPLETED

    @property
    def is_terminal(self) -> bool:
        return self.state in (
            AttackNodeState.COMPLETED,
            AttackNodeState.FAILED,
            AttackNodeState.BLOCKED,
            AttackNodeState.SKIPPED,
        )
