"""AttackPlanner — the top-level pipeline orchestrator.

Pipeline: Target -> Capability Discovery -> Attack Selection ->
Dependency Resolution -> Ordering -> Strategy Assignment -> AttackPlan.

AttackPlanner depends only on Protocols (protocols.py) — every stage is
injected, swappable, and independently testable. This class contains
NO attack-selection logic, NO ordering logic, and NO strategy logic
itself; it only sequences calls to the protocols it was given. That is
the entire point of "no hardcoded orchestration": replacing any stage
never requires touching this file.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.planning.entity import AttackPlan
from redforge.domain.planning.exceptions import AttackPlanCycleError, NoCompatibleAttacksError
from redforge.domain.planning.planning_strategies import (
    STRATEGY_REGISTRY,
    DefaultDependencyResolver,
    DefaultOrderingPolicy,
    DefaultSelectionPolicy,
    default_priority_of,
)
from redforge.domain.planning.value_objects import (
    EstimatedCost,
    EstimatedDuration,
    PlanningStrategy,
    RiskAppetite,
    SelectionCriteria,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from redforge.domain.attack_library.entity import AttackDefinition
    from redforge.domain.attack_library.repository import AttackLibraryRepository
    from redforge.domain.attack_library.taxonomy import AttackTaxonomyRepository
    from redforge.domain.planning.protocols import (
        CapabilityResolver,
        DependencyResolver,
        OrderingPolicy,
        SelectionPolicy,
        StrategyProtocol,
    )
    from redforge.domain.planning.value_objects import AttackPriority
    from redforge.shared.identifiers import EntityId


class AttackPlanner:
    """Default PlannerProtocol implementation.

    Every collaborator has a sensible default (see planning_strategies.py)
    but can be overridden at construction time — this is the seam
    "support future adaptive planning" refers to: a smarter
    SelectionPolicy or OrderingPolicy slots in here without any change
    to the pipeline sequencing itself.
    """

    def __init__(
        self,
        attack_repository: AttackLibraryRepository,
        capability_resolver: CapabilityResolver,
        *,
        taxonomy_repository: AttackTaxonomyRepository | None = None,
        selection_policy: SelectionPolicy | None = None,
        dependency_resolver: DependencyResolver | None = None,
        ordering_policy: OrderingPolicy | None = None,
        strategy_registry: dict[PlanningStrategy, StrategyProtocol] | None = None,
        priority_of: Callable[[AttackDefinition], AttackPriority] | None = None,
    ) -> None:
        self._attack_repository = attack_repository
        self._capability_resolver = capability_resolver
        self._taxonomy_repository = taxonomy_repository
        self._selection_policy: SelectionPolicy = selection_policy or DefaultSelectionPolicy()
        self._dependency_resolver: DependencyResolver = (
            dependency_resolver or DefaultDependencyResolver()
        )
        self._ordering_policy: OrderingPolicy = ordering_policy or DefaultOrderingPolicy()
        self._strategy_registry = strategy_registry or STRATEGY_REGISTRY
        self._priority_of = priority_of or default_priority_of

    async def plan(
        self,
        target_id: EntityId,
        organization_id: EntityId,
        strategy: PlanningStrategy,
        *,
        policy_id: EntityId | None = None,
        risk_appetite: RiskAppetite = RiskAppetite.BALANCED,
        criteria: SelectionCriteria | None = None,
        taxonomy_scope_node_id: EntityId | None = None,
    ) -> AttackPlan:
        """Run the full planning pipeline and produce an immutable
        AttackPlan.

        Raises:
            NoCompatibleAttacksError: If capability/criteria filtering
                leaves zero candidate attacks.
            AttackPlanCycleError: If the selected attacks' declared
                relationships form a dependency cycle.
            PlanningStrategyNotImplementedError: If `strategy` has no
                working StrategyProtocol implementation yet.
        """
        effective_criteria = criteria or SelectionCriteria(risk_appetite=risk_appetite)

        # ── Capability Discovery ────────────────────────────────────
        available_capabilities = await self._capability_resolver.resolve(target_id)

        # ── Attack Selection ────────────────────────────────────────
        candidates = await self._load_candidates(taxonomy_scope_node_id)
        selected = self._selection_policy.select(
            candidates, effective_criteria, available_capabilities,
        )
        if not selected:
            raise NoCompatibleAttacksError(
                str(target_id), ",".join(sorted(available_capabilities)) or "(none)",
            )

        # ── Dependency Resolution ───────────────────────────────────
        dependency_graph = self._dependency_resolver.resolve(selected)

        # ── Ordering ─────────────────────────────────────────────────
        try:
            sequence = self._ordering_policy.order(
                selected, dependency_graph, self._priority_of,
            )
        except ValueError as exc:
            raise AttackPlanCycleError(str(target_id), str(exc)) from exc

        # ── Strategy Assignment ─────────────────────────────────────
        strategy_impl = self._strategy_registry[strategy]
        final_sequence = strategy_impl.apply(sequence)

        # ── AttackPlan ───────────────────────────────────────────────
        # `selected` is guaranteed non-empty here (checked above).
        evaluation_requirements = frozenset().union(
            *(a.evaluation_requirements for a in selected)
        )
        expected_outcomes = frozenset().union(
            *(a.expected_outcomes for a in selected)
        )

        return AttackPlan.create(
            target_id=target_id,
            organization_id=organization_id,
            strategy=strategy,
            sequence=final_sequence,
            dependency_graph=dependency_graph,
            policy_id=policy_id,
            risk_appetite=effective_criteria.risk_appetite,
            estimated_cost=self._estimate_cost(selected),
            estimated_duration=self._estimate_duration(selected),
            evaluation_requirements=evaluation_requirements,
            expected_outcomes=expected_outcomes,
            risk_level=self._estimate_risk_level(selected),
        )

    async def _load_candidates(
        self, taxonomy_scope_node_id: EntityId | None,
    ) -> tuple[AttackDefinition, ...]:
        candidates = tuple(await self._attack_repository.list_executable())
        if taxonomy_scope_node_id is None:
            return candidates
        if self._taxonomy_repository is None:
            raise ValueError(
                "taxonomy_scope_node_id was given but no taxonomy_repository "
                "was provided to AttackPlanner"
            )
        descendants = await self._taxonomy_repository.get_descendants(taxonomy_scope_node_id)
        in_scope = {taxonomy_scope_node_id} | {d.id for d in descendants}
        return tuple(a for a in candidates if a.taxonomy_node_id in in_scope)

    @staticmethod
    def _estimate_cost(selected: tuple[AttackDefinition, ...]) -> EstimatedCost:
        """A simple, transparent per-attack heuristic — one request and
        a fixed token estimate per selected attack. Real cost estimation
        (using Provider.CostModel and actual payload sizes) is
        application-layer/infrastructure work; this domain-layer
        heuristic exists so AttackPlan always has *a* cost estimate,
        never a fabricated-precision one."""
        return EstimatedCost(
            request_estimate=len(selected),
            token_estimate=len(selected) * 500,
            monetary_estimate_usd=0.0,
        )

    @staticmethod
    def _estimate_duration(selected: tuple[AttackDefinition, ...]) -> EstimatedDuration:
        return EstimatedDuration(seconds=len(selected) * 5)

    @staticmethod
    def _estimate_risk_level(selected: tuple[AttackDefinition, ...]) -> str:
        severities = {str(a.severity) for a in selected}
        if "critical" in severities:
            return "critical"
        if "high" in severities:
            return "high"
        if "medium" in severities:
            return "medium"
        return "low"
