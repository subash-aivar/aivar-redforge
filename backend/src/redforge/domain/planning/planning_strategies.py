"""Default implementations of the planning pipeline Protocols.

Every class here is swappable — AttackPlanner depends on the Protocols
(protocols.py), never on these classes directly. These are the
platform's reasonable, reviewed defaults, not the only possible ones.

No switch statements: strategy dispatch is a dict keyed by
PlanningStrategy (STRATEGY_REGISTRY), built from data, not an if/elif
chain over enum members.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from redforge.domain.attack_library.value_objects import (
    AttackMaturity,
    AttackRelationshipType,
    Capability,
    SafetyClassification,
)
from redforge.domain.planning.exceptions import PlanningStrategyNotImplementedError
from redforge.domain.planning.value_objects import (
    AttackDependencyGraph,
    AttackPriority,
    AttackSequence,
    PlannedAttackStep,
    PlanningStrategy,
    RiskAppetite,
    SelectionCriteria,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from redforge.domain.attack_library.entity import AttackDefinition
    from redforge.domain.planning.protocols import StrategyProtocol
    from redforge.shared.identifiers import EntityId

# ─── Priority ───────────────────────────────────────────────────────────────

_SEVERITY_TO_PRIORITY = {
    "critical": AttackPriority.CRITICAL,
    "high": AttackPriority.HIGH,
    "medium": AttackPriority.MEDIUM,
    "low": AttackPriority.LOW,
    "informational": AttackPriority.LOW,
}

_PRIORITY_RANK = {
    AttackPriority.CRITICAL: 0,
    AttackPriority.HIGH: 1,
    AttackPriority.MEDIUM: 2,
    AttackPriority.LOW: 3,
}


def default_priority_of(attack: AttackDefinition) -> AttackPriority:
    """Map an attack's severity to a planning priority. The default,
    swappable mapping: risk-appetite-aware prioritization (e.g.
    boosting reconnaissance-value LOW-severity attacks under an
    AGGRESSIVE appetite) is exactly the kind of alternative
    `priority_of` callable AttackPlanner accepts instead of this one —
    see AttackPlanner.__init__'s `priority_of` parameter.
    """
    return _SEVERITY_TO_PRIORITY[str(attack.severity)]


# ─── CapabilityResolver ─────────────────────────────────────────────────────


class StaticCapabilityResolver:
    """A CapabilityResolver backed by a fixed, caller-supplied mapping.

    The real, production CapabilityResolver needs to combine data from
    the AI Targets and Providers bounded contexts (application-layer
    repository reads) — out of scope for this sprint (see the sprint
    report's technical debt). This implementation is what tests and
    simple deployments use today, and is a legitimate permanent option
    for callers who already know a target's capabilities out-of-band.
    """

    def __init__(self, capabilities_by_target: dict[str, frozenset[str]]) -> None:
        self._capabilities_by_target = capabilities_by_target

    async def resolve(self, target_id: EntityId) -> frozenset[str]:
        return self._capabilities_by_target.get(str(target_id), frozenset())


# ─── SelectionPolicy ────────────────────────────────────────────────────────


class DefaultSelectionPolicy:
    """Selects executable, capability-compatible attacks matching
    criteria, filtered by risk appetite, deduplicated by identity.

    Risk appetite effect (a real, documented behavior — not just stored
    metadata): CONSERVATIVE excludes DESTRUCTIVE/RESTRICTED-safety
    attacks; BALANCED excludes RESTRICTED only; AGGRESSIVE excludes
    nothing on safety grounds.
    """

    _SAFETY_CEILING: ClassVar[dict[RiskAppetite, frozenset[SafetyClassification]]] = {
        RiskAppetite.CONSERVATIVE: frozenset({SafetyClassification.SAFE}),
        RiskAppetite.BALANCED: frozenset({
            SafetyClassification.SAFE, SafetyClassification.CAUTION,
            SafetyClassification.DESTRUCTIVE,
        }),
        RiskAppetite.AGGRESSIVE: frozenset({
            SafetyClassification.SAFE, SafetyClassification.CAUTION,
            SafetyClassification.DESTRUCTIVE, SafetyClassification.RESTRICTED,
        }),
    }

    def select(
        self,
        candidates: tuple[AttackDefinition, ...],
        criteria: SelectionCriteria,
        available_capabilities: frozenset[str],
    ) -> tuple[AttackDefinition, ...]:
        allowed_safety = self._SAFETY_CEILING[criteria.risk_appetite]
        seen_ids: set[str] = set()
        selected: list[AttackDefinition] = []

        for attack in candidates:
            if str(attack.id) in seen_ids:
                continue
            if not attack.is_executable:
                continue
            if attack.safety not in allowed_safety:
                continue
            is_experimental = attack.maturity == AttackMaturity.EXPERIMENTAL
            if not criteria.include_experimental and is_experimental:
                continue
            if (
                criteria.required_categories
                and str(attack.category) not in criteria.required_categories
            ):
                continue
            if attack.tags & criteria.excluded_tags:
                continue
            if (
                criteria.policy_attack_ids is not None
                and attack.id not in criteria.policy_attack_ids
            ):
                continue
            required = {c.value for c in attack.required_capabilities}
            if not required.issubset(available_capabilities):
                continue

            seen_ids.add(str(attack.id))
            selected.append(attack)

        return tuple(selected)


# ─── DependencyResolver ─────────────────────────────────────────────────────

# Only these relationship types carry real "must run before" execution
# semantics for planning purposes. PARENT_OF/DERIVED_FROM are taxonomic
# lineage relationships (classification), not execution ordering
# constraints — deliberately excluded, not an oversight.
_DEPENDENCY_RELATIONSHIP_TYPES = frozenset({
    AttackRelationshipType.PREREQUISITE_OF,
    AttackRelationshipType.COMPOSED_OF,
})


class DefaultDependencyResolver:
    """Builds a dependency graph from each attack's own declared
    AttackRelationship edges (Sprint 13's relationship model — reused,
    not re-declared)."""

    def resolve(self, selected: tuple[AttackDefinition, ...]) -> AttackDependencyGraph:
        selected_ids = {a.id for a in selected}
        edges: set[tuple[EntityId, EntityId]] = set()
        for attack in selected:
            for relationship in attack.relationships:
                if relationship.relationship_type not in _DEPENDENCY_RELATIONSHIP_TYPES:
                    continue
                if relationship.related_attack_id not in selected_ids:
                    # The related attack wasn't selected — nothing to
                    # depend on within this plan. Not an error: a
                    # prerequisite pointing outside the selected set
                    # just means that edge is inapplicable to this
                    # particular plan, not that the plan is invalid.
                    continue
                edges.add((attack.id, relationship.related_attack_id))
        return AttackDependencyGraph(edges=frozenset(edges))


# ─── OrderingPolicy ─────────────────────────────────────────────────────────


class DefaultOrderingPolicy:
    """Topologically valid, priority-weighted, category-grouped ordering.

    Grouping by category mirrors the existing
    application.execution_graph.ExecutionPlanner.plan_by_category
    precedent — the same "group related attacks together" idea, applied
    here at the canonical-plan level rather than the runtime-dispatch
    level.
    """

    def order(
        self,
        selected: tuple[AttackDefinition, ...],
        graph: AttackDependencyGraph,
        priority_of: Callable[[AttackDefinition], AttackPriority],
    ) -> AttackSequence:
        by_id = {a.id: a for a in selected}
        ids = frozenset(by_id)

        def key(attack_id: EntityId) -> tuple[int, str]:
            return (_PRIORITY_RANK[priority_of(by_id[attack_id])], str(attack_id))

        ordered_ids = graph.topological_order(ids, priority_key=key)

        steps = tuple(
            PlannedAttackStep(
                attack_id=attack_id,
                order=index,
                group=str(by_id[attack_id].category),
                priority=priority_of(by_id[attack_id]),
                required_capabilities=by_id[attack_id].required_capabilities,
                depends_on=graph.depends_on(attack_id),
            )
            for index, attack_id in enumerate(ordered_ids)
        )
        return AttackSequence(steps=steps)


def is_topologically_valid(steps: tuple[PlannedAttackStep, ...]) -> bool:
    """Verify every step's dependencies appear earlier in `steps` than
    the step itself. Used by strategies that reorder or regroup an
    already-valid AttackSequence, as a cheap safety net against
    accidentally producing an invalid order."""
    scheduled: set[EntityId] = set()
    for step in steps:
        if not step.depends_on.issubset(scheduled):
            return False
        scheduled.add(step.attack_id)
    return True


def _renumber(steps: tuple[PlannedAttackStep, ...]) -> tuple[PlannedAttackStep, ...]:
    return tuple(
        PlannedAttackStep(
            attack_id=s.attack_id, order=i, group=s.group, priority=s.priority,
            required_capabilities=s.required_capabilities, depends_on=s.depends_on,
        )
        for i, s in enumerate(steps)
    )


# ─── StrategyProtocol implementations ───────────────────────────────────────


class PassthroughStrategy:
    """No reshaping — the OrderingPolicy's output is used as-is.
    Used for SINGLE_STEP's underlying step order (grouping is what
    changes, not order) and as the base for strategies that only touch
    group labels."""

    def apply(self, sequence: AttackSequence) -> AttackSequence:
        return sequence


class SingleStepStrategy:
    """Collapses the plan into one execution group — every attack still
    runs in its dependency-safe order, but as a single homogeneous
    stage rather than the category-based grouping OrderingPolicy
    produced by default."""

    def apply(self, sequence: AttackSequence) -> AttackSequence:
        steps = tuple(
            PlannedAttackStep(
                attack_id=s.attack_id, order=s.order, group="single_step",
                priority=s.priority, required_capabilities=s.required_capabilities,
                depends_on=s.depends_on,
            )
            for s in sequence.steps
        )
        return AttackSequence(steps=steps)


class _PriorityGroupReorderStrategy:
    """Shared implementation for ESCALATION (ascending) and RISK_DRIVEN
    (descending): reorder whole groups relative to each other by their
    minimum priority rank, never reordering steps *within* a group or
    breaking any dependency — safety verified via is_topologically_valid
    before returning."""

    def __init__(self, *, ascending: bool) -> None:
        self._ascending = ascending

    def apply(self, sequence: AttackSequence) -> AttackSequence:
        groups = sequence.groups
        group_rank = {
            g: min(_PRIORITY_RANK[s.priority] for s in sequence.steps_in_group(g))
            for g in groups
        }
        ordered_groups = sorted(groups, key=lambda g: group_rank[g], reverse=not self._ascending)

        reordered = tuple(
            step
            for group in ordered_groups
            for step in sequence.steps_in_group(group)
        )
        reordered = _renumber(reordered)
        if not is_topologically_valid(reordered):
            # A cross-group dependency made this regrouping unsafe —
            # fall back to the original, already-valid order rather
            # than emit a broken plan.
            return sequence
        return AttackSequence(steps=reordered)


class EscalationStrategy(_PriorityGroupReorderStrategy):
    """Runs lower-priority groups first, escalating toward the highest
    — gradual pressure increase rather than opening with the biggest
    attacks."""

    def __init__(self) -> None:
        super().__init__(ascending=True)


class RiskDrivenStrategy(_PriorityGroupReorderStrategy):
    """The mirror of Escalation: highest-priority (highest-risk) groups
    first, front-loading the attacks the platform's risk appetite
    considers most worth running early (e.g. if the plan gets cut
    short, the highest-value attacks already ran)."""

    def __init__(self) -> None:
        super().__init__(ascending=False)


class ReconFirstStrategy:
    """Promotes reconnaissance-value attacks (tagged "recon" or
    category MODEL_EXTRACTION) to a leading group, ahead of everything
    else — dependency-safety verified the same way as the priority
    reorder strategies."""

    _RECON_CATEGORY = "model_extraction"

    def apply(self, sequence: AttackSequence) -> AttackSequence:
        def is_recon(step: PlannedAttackStep) -> bool:
            return step.group == self._RECON_CATEGORY

        recon_steps = tuple(s for s in sequence.steps if is_recon(s))
        other_steps = tuple(s for s in sequence.steps if not is_recon(s))
        if not recon_steps:
            return sequence

        reordered = _renumber(recon_steps + other_steps)
        if not is_topologically_valid(reordered):
            return sequence
        return AttackSequence(steps=reordered)


class ParallelStrategy:
    """Groups steps into dependency-safe 'waves': a step's wave is
    1 + max(wave of its dependencies), or 0 if it has none — every step
    within a wave can run concurrently, since none of them depend on
    another step in the same wave. Order is preserved; only grouping
    changes, so this can never violate a dependency."""

    def apply(self, sequence: AttackSequence) -> AttackSequence:
        wave_of: dict[EntityId, int] = {}
        for step in sequence.steps:
            if not step.depends_on:
                wave_of[step.attack_id] = 0
            else:
                wave_of[step.attack_id] = 1 + max(
                    wave_of[dep] for dep in step.depends_on
                )

        steps = tuple(
            PlannedAttackStep(
                attack_id=s.attack_id, order=s.order, group=f"wave_{wave_of[s.attack_id]}",
                priority=s.priority, required_capabilities=s.required_capabilities,
                depends_on=s.depends_on,
            )
            for s in sequence.steps
        )
        return AttackSequence(steps=steps)


class CapabilityDrivenStrategy:
    """Groups steps purely by their required-capability signature —
    attacks needing the exact same target capabilities are batched
    together, useful for capability-gated execution backends that want
    to set up/tear down capability access once per batch rather than
    per attack."""

    def apply(self, sequence: AttackSequence) -> AttackSequence:
        def signature(caps: frozenset[Capability]) -> str:
            return ",".join(sorted(c.value for c in caps)) or "none"

        steps = tuple(
            PlannedAttackStep(
                attack_id=s.attack_id, order=s.order,
                group=f"caps:{signature(s.required_capabilities)}",
                priority=s.priority, required_capabilities=s.required_capabilities,
                depends_on=s.depends_on,
            )
            for s in sequence.steps
        )
        return AttackSequence(steps=steps)


class AdaptiveStrategy:
    """Structurally adapts grouping to the target's capability profile
    and dependency shape by combining wave-leveling (ParallelStrategy)
    with capability-signature grouping — attacks in the same
    concurrency wave AND needing the same capabilities are batched.

    Honest scope note: this is structural adaptation to the *input*
    (capabilities, dependency shape), not runtime-feedback adaptation
    (reacting to execution results) — the latter would require an
    execution engine and evaluation results, both explicitly out of
    scope for this sprint. PlanningStrategy.ADAPTIVE is functional
    today under this narrower, honest definition; true feedback-driven
    adaptive planning is future work, same as MULTI_TURN/AUTONOMOUS.
    """

    def apply(self, sequence: AttackSequence) -> AttackSequence:
        wave_of: dict[EntityId, int] = {}
        for step in sequence.steps:
            wave_of[step.attack_id] = (
                0 if not step.depends_on
                else 1 + max(wave_of[dep] for dep in step.depends_on)
            )

        def signature(caps: frozenset[Capability]) -> str:
            return ",".join(sorted(c.value for c in caps)) or "none"

        steps = tuple(
            PlannedAttackStep(
                attack_id=s.attack_id, order=s.order,
                group=f"wave_{wave_of[s.attack_id]}:{signature(s.required_capabilities)}",
                priority=s.priority, required_capabilities=s.required_capabilities,
                depends_on=s.depends_on,
            )
            for s in sequence.steps
        )
        return AttackSequence(steps=steps)


class PolicyDrivenStrategy:
    """Identity passthrough — deliberately.

    "Policy-driven" planning is realized at the SELECTION stage
    (SelectionCriteria.policy_attack_ids restricts candidates to a
    Validation Policy's attack set — see DefaultSelectionPolicy and
    AttackPlanner), not by reshaping an already-ordered sequence:
    domain.policies.entity.ValidationPolicy stores its attacks as a
    plain, unordered `set[EntityId]` (verified by inspection), so there
    is no ordering signal in a policy for a *strategy* stage to apply.
    By the time this strategy runs, the policy's only real influence
    (which attacks are even candidates) has already taken full effect.
    """

    def apply(self, sequence: AttackSequence) -> AttackSequence:
        return sequence


class _NotImplementedStrategy:
    """Registered placeholder for PlanningStrategy members with no
    working implementation yet (MULTI_TURN, AUTONOMOUS) — raises a
    specific, catchable exception rather than silently no-op'ing or
    raising a generic NotImplementedError indistinguishable from a bug.
    """

    def __init__(self, strategy: PlanningStrategy) -> None:
        self._strategy = strategy

    def apply(self, sequence: AttackSequence) -> AttackSequence:
        raise PlanningStrategyNotImplementedError(str(self._strategy))


STRATEGY_REGISTRY: dict[PlanningStrategy, StrategyProtocol] = {
    PlanningStrategy.SINGLE_STEP: SingleStepStrategy(),
    PlanningStrategy.PROGRESSIVE: EscalationStrategy(),
    PlanningStrategy.ESCALATION: EscalationStrategy(),
    PlanningStrategy.RECON_FIRST: ReconFirstStrategy(),
    PlanningStrategy.ADAPTIVE: AdaptiveStrategy(),
    PlanningStrategy.PARALLEL: ParallelStrategy(),
    PlanningStrategy.CAPABILITY_DRIVEN: CapabilityDrivenStrategy(),
    PlanningStrategy.RISK_DRIVEN: RiskDrivenStrategy(),
    PlanningStrategy.POLICY_DRIVEN: PolicyDrivenStrategy(),
    PlanningStrategy.MULTI_TURN: _NotImplementedStrategy(PlanningStrategy.MULTI_TURN),
    PlanningStrategy.AUTONOMOUS: _NotImplementedStrategy(PlanningStrategy.AUTONOMOUS),
}
