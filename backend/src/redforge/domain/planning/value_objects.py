"""Value objects for the Attack Planning & Strategy bounded context.

This is the canonical model for WHAT to execute, WHEN, WHY, and in
WHICH ORDER — deliberately not payload generation or execution itself.

Naming note (read before adding anything named "AttackPlan" or
"ExecutionStrategy" elsewhere): three other, genuinely different
concepts already share adjacent names in this codebase:
  - `application.runtime.attacks.contracts.AttackPlan` — a SINGLE
    attack's conversation-turn plan (how one attack's dialogue
    unfolds). Different altitude entirely: that's "how does this one
    attack talk", this is "which attacks, in what order, across a
    whole target".
  - `domain.execution.entity.ExecutionPlan` — the RUNTIME tracker
    (stages/steps/status/retries) that DISPATCHES an already-decided
    attack order. This bounded context produces the ordering that
    feeds it; it does not replace it.
  - Three pre-existing `ExecutionStrategy` enums (attack_library:
    per-attack turn shape; policies: SEQUENTIAL/PARALLEL/ADAPTIVE
    execution mode). The planning-level strategy concept here is
    named `PlanningStrategy`, not `ExecutionStrategy`, specifically to
    avoid a fourth collision.

Reuse, not duplication: `FailureStrategy`/`RetryPolicy`/`TimeoutPolicy`
are imported directly from `domain.execution.value_objects` (this
plan's policy fields are literally consumed by that context downstream
— reusing the same types is the point, not an accident).
`EvaluationRequirement`/`ExpectedOutcome` are imported from
`domain.attack_library.value_objects` for the same reason: an
AttackPlan's aggregate requirements are drawn from its steps' own
attack-level declarations, and both should be the same
Python type. `Confidence` is imported from `domain.evidence.value_objects`
(a plan's confidence in its own selections uses the exact same 0.0-1.0
scale evidence confidence already uses — no reason to invent a second
Confidence type in a third context).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, unique
from typing import TYPE_CHECKING, Any

from redforge.domain.attack_library.value_objects import (
    Capability,
    EvaluationRequirement,
    ExpectedOutcome,
)
from redforge.domain.evidence.value_objects import Confidence
from redforge.domain.execution.value_objects import FailureStrategy, RetryPolicy

if TYPE_CHECKING:
    from collections.abc import Callable

    from redforge.shared.identifiers import EntityId

__all__ = [
    "AttackDependencyGraph",
    "AttackPriority",
    "AttackSequence",
    "Confidence",
    "EstimatedCost",
    "EstimatedDuration",
    "EvaluationRequirement",
    "ExpectedOutcome",
    "FailureStrategy",
    "PlanStatus",
    "PlannedAttackStep",
    "PlanningStrategy",
    "RetryPolicy",
    "RiskAppetite",
    "SelectionCriteria",
    "SuccessCriteria",
]


@unique
class PlanningStrategy(StrEnum):
    """How a campaign-level attack plan is shaped and sequenced.

    MULTI_TURN and AUTONOMOUS are declared now (so callers and tests
    can reference stable names without a future breaking enum change)
    but have no functioning StrategyProtocol implementation this
    sprint — see planning_strategies.py's registry and
    PlanningStrategyNotImplementedError. Declaring the seam without
    building the engine behind it is the same "future work" pattern
    Sprint 13 used for MULTI_TURN/AUTOMATED_AGENT on
    attack_library.ExecutionStrategy.
    """

    SINGLE_STEP = "single_step"
    PROGRESSIVE = "progressive"
    ESCALATION = "escalation"
    RECON_FIRST = "recon_first"
    ADAPTIVE = "adaptive"
    PARALLEL = "parallel"
    CAPABILITY_DRIVEN = "capability_driven"
    RISK_DRIVEN = "risk_driven"
    POLICY_DRIVEN = "policy_driven"
    MULTI_TURN = "multi_turn"
    AUTONOMOUS = "autonomous"


@unique
class RiskAppetite(StrEnum):
    """How aggressively a plan should select and prioritize attacks.

    No risk-appetite concept existed anywhere in the platform before
    this sprint (verified by repository-wide search) — this is new
    territory, not a reuse of an existing enum.
    """

    CONSERVATIVE = "conservative"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"


@unique
class AttackPriority(StrEnum):
    """Execution urgency of a planned step.

    Deliberately distinct from AttackSeverity (attack_library): severity
    is "how bad is this if it succeeds"; priority is "how urgently
    should we run this, given risk appetite and planning strategy" —
    two attacks of equal severity can have different priority (e.g. a
    recon-value attack gets elevated priority under RECON_FIRST despite
    LOW severity).
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@unique
class PlanStatus(StrEnum):
    """Lifecycle status of an AttackPlan.

    Only two states: a plan is either the active plan for its target,
    or it has been superseded by a newer plan (a replan). There is no
    "draft"/"executing" state here — this bounded context produces a
    complete, immutable artifact in one shot (AttackPlan.create()); any
    in-progress execution state belongs to domain.execution.ExecutionPlan,
    which consumes this plan's ordering, not this aggregate.
    """

    ACTIVE = "active"
    SUPERSEDED = "superseded"


@dataclass(frozen=True, slots=True)
class SelectionCriteria:
    """Input criteria a SelectionPolicy filters attack candidates against.

    `policy_attack_ids`: when a Validation Policy is supplied, its
    attack set restricts selection to exactly those attacks (still
    subject to capability/criteria filtering — a policy cannot force an
    incompatible attack into the plan). This is how "Policy-driven"
    planning is realized: at selection time, not by post-hoc reordering
    — a Validation Policy's attack set carries no ordering information
    of its own (see domain.policies.entity.ValidationPolicy, which
    stores attacks as a plain `set[EntityId]`), so there is nothing for
    a policy-driven *strategy* to reshape beyond what selection already
    determined. See PolicyDrivenStrategy's docstring.
    """

    risk_appetite: RiskAppetite = RiskAppetite.BALANCED
    required_categories: frozenset[str] = frozenset()
    excluded_tags: frozenset[str] = frozenset()
    include_experimental: bool = False
    policy_attack_ids: frozenset[EntityId] | None = None


@dataclass(frozen=True, slots=True)
class PlannedAttackStep:
    """One attack's place within an AttackSequence."""

    attack_id: EntityId
    order: int
    group: str
    priority: AttackPriority
    required_capabilities: frozenset[Capability] = frozenset()
    depends_on: frozenset[EntityId] = frozenset()

    def __post_init__(self) -> None:
        if self.order < 0:
            raise ValueError("order must be non-negative")
        if self.attack_id in self.depends_on:
            raise ValueError("an attack cannot depend on itself")


@dataclass(frozen=True, slots=True)
class AttackSequence:
    """The ordered, deduplicated set of steps an AttackPlan will run.

    Validated at construction: no duplicate attack_id across steps (see
    mission requirement "remove duplicates" — enforced as an invariant,
    not left to callers to get right), and every `depends_on` reference
    resolves to another step actually present in this sequence.
    """

    steps: tuple[PlannedAttackStep, ...]

    def __post_init__(self) -> None:
        attack_ids = [s.attack_id for s in self.steps]
        if len(attack_ids) != len(set(attack_ids)):
            duplicates = {a for a in attack_ids if attack_ids.count(a) > 1}
            raise ValueError(
                f"AttackSequence contains duplicate attack_id(s): "
                f"{sorted(str(d) for d in duplicates)}"
            )
        known = set(attack_ids)
        for step in self.steps:
            missing = step.depends_on - known
            if missing:
                raise ValueError(
                    f"Step {step.attack_id} depends on attack(s) not present "
                    f"in this sequence: {sorted(str(m) for m in missing)}"
                )

    @property
    def attack_ids(self) -> tuple[EntityId, ...]:
        return tuple(s.attack_id for s in self.steps)

    @property
    def groups(self) -> tuple[str, ...]:
        """Distinct group names, in first-seen order."""
        seen: list[str] = []
        for step in self.steps:
            if step.group not in seen:
                seen.append(step.group)
        return tuple(seen)

    def steps_in_group(self, group: str) -> tuple[PlannedAttackStep, ...]:
        return tuple(s for s in self.steps if s.group == group)

    def __len__(self) -> int:
        return len(self.steps)


@dataclass(frozen=True, slots=True)
class AttackDependencyGraph:
    """A pure-data directed dependency graph over attack_ids: (a, b)
    means "a depends on b" (b must run before a).

    This is a domain-layer-only graph for planning-time validation
    (cycle detection at plan construction) and ordering computation —
    deliberately NOT the same machinery as
    application.execution_graph.AttackGraph, which is a heavier,
    application-layer, runtime-facing structure (node statuses,
    retries, timeouts, critical-path analysis for dispatch). Domain
    cannot import application (ADR-0001), so a second, minimal
    topological-sort implementation here is the same accepted tradeoff
    Sprint 13 made for AttackTaxonomyNode's ancestor-walk cycle check
    existing alongside KnowledgeGraph's separate cycle detection: two
    different layers, two different purposes, unavoidable given the
    layering rule — not an oversight.
    """

    edges: frozenset[tuple[EntityId, EntityId]] = field(default_factory=frozenset)

    def depends_on(self, attack_id: EntityId) -> frozenset[EntityId]:
        return frozenset(dep for (a, dep) in self.edges if a == attack_id)

    def dependents_of(self, attack_id: EntityId) -> frozenset[EntityId]:
        return frozenset(a for (a, dep) in self.edges if dep == attack_id)

    def topological_order(
        self,
        nodes: frozenset[EntityId],
        priority_key: Callable[[EntityId], Any] | None = None,
    ) -> tuple[EntityId, ...]:
        """Kahn's algorithm. Raises ValueError if `nodes` (plus this
        graph's edges restricted to `nodes`) contains a cycle.

        `nodes` is passed explicitly (rather than inferred from edges)
        so a node with no dependency edges at all is still included in
        the ordering — a graph only knows about edges, not about
        isolated nodes.

        `priority_key`: when multiple nodes are simultaneously "ready"
        (all their dependencies are already scheduled), ties are broken
        by this key instead of alphabetically by ID — this is how
        OrderingPolicy produces a priority-weighted order that is still
        guaranteed topologically valid (priority only decides *which*
        ready node goes next, never violates a dependency).
        """
        key = priority_key or str
        relevant_edges = [
            (a, dep) for (a, dep) in self.edges if a in nodes and dep in nodes
        ]
        in_degree: dict[EntityId, int] = dict.fromkeys(nodes, 0)
        adjacency: dict[EntityId, list[EntityId]] = {n: [] for n in nodes}
        for a, dep in relevant_edges:
            # edge (a, dep) = "a depends on dep" => dep must precede a.
            adjacency[dep].append(a)
            in_degree[a] += 1

        ready = sorted((n for n in nodes if in_degree[n] == 0), key=key)
        ordered: list[EntityId] = []
        while ready:
            current = ready.pop(0)
            ordered.append(current)
            for successor in sorted(adjacency[current], key=key):
                in_degree[successor] -= 1
                if in_degree[successor] == 0:
                    ready.append(successor)
            ready.sort(key=key)

        if len(ordered) != len(nodes):
            remaining = nodes - set(ordered)
            raise ValueError(
                f"Dependency graph contains a cycle among: "
                f"{sorted(str(n) for n in remaining)}"
            )
        return tuple(ordered)


@dataclass(frozen=True, slots=True)
class EstimatedCost:
    """Rough resource cost estimate for running a plan."""

    request_estimate: int = 0
    token_estimate: int = 0
    monetary_estimate_usd: float = 0.0

    def __post_init__(self) -> None:
        if self.request_estimate < 0 or self.token_estimate < 0:
            raise ValueError("estimates must be non-negative")
        if self.monetary_estimate_usd < 0.0:
            raise ValueError("monetary_estimate_usd must be non-negative")


@dataclass(frozen=True, slots=True)
class EstimatedDuration:
    """Rough wall-clock duration estimate for running a plan."""

    seconds: int

    def __post_init__(self) -> None:
        if self.seconds < 0:
            raise ValueError("seconds must be non-negative")


@dataclass(frozen=True, slots=True)
class SuccessCriteria:
    """What "this plan accomplished its purpose" means, at the plan
    level — distinct from any single step's ExpectedOutcome."""

    description: str
    minimum_findings: int = 0

    def __post_init__(self) -> None:
        if not self.description:
            raise ValueError("description must not be empty")
        if self.minimum_findings < 0:
            raise ValueError("minimum_findings must be non-negative")
