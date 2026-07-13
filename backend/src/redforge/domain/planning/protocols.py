"""Protocols for the Attack Planning & Strategy pipeline.

Every stage of the pipeline (Capability Discovery -> Attack Selection
-> Dependency Resolution -> Ordering -> Strategy Assignment -> AttackPlan)
is a Protocol here, not a concrete class the orchestrator hardcodes —
swapping any stage (e.g. a smarter SelectionPolicy that scores by
historical finding rate, once that data exists) never requires touching
AttackPlanner or any other stage's code. This is what "support future
adaptive planning" means structurally: the seam already exists.

No switch statements: AttackPlanner dispatches to a StrategyProtocol
via a dict lookup keyed by PlanningStrategy (see planning_strategies.py),
not an if/elif chain.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Callable

    from redforge.domain.attack_library.entity import AttackDefinition
    from redforge.domain.planning.entity import AttackPlan
    from redforge.domain.planning.value_objects import (
        AttackDependencyGraph,
        AttackPriority,
        AttackSequence,
        PlanningStrategy,
        RiskAppetite,
        SelectionCriteria,
    )
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class CapabilityResolver(Protocol):
    """Determines what capabilities a target actually exposes.

    Deliberately takes only a target_id, not an AITarget entity: the
    real implementation needs to combine data from the AI Targets and
    Providers bounded contexts (an application-layer concern, touching
    two repositories), which the planning domain layer must not import
    directly. See planning_strategies.StaticCapabilityResolver for the
    test/simple-deployment default; a real AITarget+Provider-backed
    resolver is application-layer infrastructure work, not built this
    sprint (see the sprint report's technical debt section).
    """

    async def resolve(self, target_id: EntityId) -> frozenset[str]:
        """Return the set of capability values (Capability.value
        strings) the target exposes."""
        ...


@runtime_checkable
class SelectionPolicy(Protocol):
    """Filters attack candidates: skips incompatible attacks (capability
    mismatch), applies selection criteria (risk appetite, category
    inclusion, tag exclusion), and removes duplicates.

    Pure and synchronous — by the time a SelectionPolicy runs, all I/O
    (loading candidates, resolving capabilities) has already happened;
    selection itself is a filtering decision over already-loaded data.
    """

    def select(
        self,
        candidates: tuple[AttackDefinition, ...],
        criteria: SelectionCriteria,
        available_capabilities: frozenset[str],
    ) -> tuple[AttackDefinition, ...]:
        """Return the subset of `candidates` that should be planned,
        deduplicated by attack identity."""
        ...


@runtime_checkable
class DependencyResolver(Protocol):
    """Builds the dependency graph for a set of selected attacks, from
    each attack's own declared AttackRelationship(PREREQUISITE_OF, ...)
    edges (see domain.attack_library — Sprint 13's relationship model,
    reused here rather than re-declared)."""

    def resolve(self, selected: tuple[AttackDefinition, ...]) -> AttackDependencyGraph:
        """Return the dependency graph restricted to attacks present in
        `selected` — a PREREQUISITE_OF edge pointing at an attack not
        in `selected` is silently dropped (that attack wasn't chosen),
        not an error; see the default implementation's docstring for
        why that's the correct behavior, not a gap."""
        ...


@runtime_checkable
class OrderingPolicy(Protocol):
    """Produces a topologically-valid, priority-weighted AttackSequence
    from selected attacks and their dependency graph."""

    def order(
        self,
        selected: tuple[AttackDefinition, ...],
        graph: AttackDependencyGraph,
        priority_of: Callable[[AttackDefinition], AttackPriority],
    ) -> AttackSequence:
        """Raises ValueError (via AttackDependencyGraph.topological_order)
        if `graph` is cyclic over `selected`'s attack_ids."""
        ...


@runtime_checkable
class StrategyProtocol(Protocol):
    """Reshapes an already-ordered AttackSequence according to a
    PlanningStrategy — e.g. RECON_FIRST promotes reconnaissance-value
    attacks to the front; PARALLEL regroups into concurrently-runnable
    groups; ESCALATION sorts ascending severity within dependency
    constraints."""

    def apply(self, sequence: AttackSequence) -> AttackSequence:
        ...


@runtime_checkable
class PlannerProtocol(Protocol):
    """The top-level pipeline orchestrator: Target -> Capability
    Discovery -> Attack Selection -> Dependency Resolution -> Ordering
    -> Strategy Assignment -> AttackPlan."""

    async def plan(
        self,
        target_id: EntityId,
        organization_id: EntityId,
        strategy: PlanningStrategy,
        *,
        policy_id: EntityId | None = None,
        risk_appetite: RiskAppetite,
        criteria: SelectionCriteria | None = None,
    ) -> AttackPlan:
        ...
