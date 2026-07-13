"""AttackPlan aggregate root.

An AttackPlan is the canonical, immutable answer to WHAT to execute,
WHEN, WHY, and in WHICH ORDER for one target — the output of the
planning pipeline (see planner.py), and the input the Execution
bounded context (domain.execution.ExecutionPlan) dispatches.

Immutability: per this sprint's mission, everything about a plan's
content is fixed at creation. The ONLY state transition is
supersede() — marking a plan retired because a newer plan replaced it,
mirroring the exact supersession pattern already used by
AttackDefinition, KnowledgeItem, and ValidationPolicy (never delete a
plan, never edit it in place; a "changed plan" is a new plan that
supersedes the old one).
"""

from __future__ import annotations

from typing import Self

from redforge.domain.planning.events import (
    AttackPlanCreated,
    AttackPlanSuperseded,
    PlanningEvent,
    _now,
)
from redforge.domain.planning.exceptions import EmptyPlanError, PlanAlreadySupersededError
from redforge.domain.planning.value_objects import (
    AttackDependencyGraph,
    AttackSequence,
    Confidence,
    EstimatedCost,
    EstimatedDuration,
    EvaluationRequirement,
    ExpectedOutcome,
    FailureStrategy,
    PlanningStrategy,
    PlanStatus,
    RetryPolicy,
    RiskAppetite,
    SuccessCriteria,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


class AttackPlan:
    """AttackPlan aggregate root.

    Invariants:
    - Always has at least one step (EmptyPlanError otherwise).
    - The dependency graph must be acyclic over this plan's attack_ids
      (enforced by the caller — see planner.py — since cycle detection
      needs graph algorithms that belong with the ordering logic, not
      duplicated again here; by the time create() runs, `sequence` is
      already a validated, ordered AttackSequence).
    - Immutable except for the single supersede() transition.
    """

    __slots__ = (
        "_confidence",
        "_dependency_graph",
        "_estimated_cost",
        "_estimated_duration",
        "_evaluation_requirements",
        "_events",
        "_expected_outcomes",
        "_failure_policy",
        "_id",
        "_metadata",
        "_organization_id",
        "_policy_id",
        "_retry_policy",
        "_risk_appetite",
        "_risk_level",
        "_sequence",
        "_status",
        "_strategy",
        "_success_criteria",
        "_superseded_by",
        "_target_id",
        "_timestamps",
    )

    def __init__(
        self,
        id: EntityId,
        target_id: EntityId,
        organization_id: EntityId,
        policy_id: EntityId | None,
        strategy: PlanningStrategy,
        risk_appetite: RiskAppetite,
        sequence: AttackSequence,
        dependency_graph: AttackDependencyGraph,
        estimated_cost: EstimatedCost,
        estimated_duration: EstimatedDuration,
        success_criteria: SuccessCriteria,
        failure_policy: FailureStrategy,
        retry_policy: RetryPolicy,
        evaluation_requirements: frozenset[EvaluationRequirement],
        expected_outcomes: frozenset[ExpectedOutcome],
        risk_level: str,
        confidence: Confidence,
        metadata: dict[str, str],
        status: PlanStatus,
        superseded_by: EntityId | None,
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._target_id = target_id
        self._organization_id = organization_id
        self._policy_id = policy_id
        self._strategy = strategy
        self._risk_appetite = risk_appetite
        self._sequence = sequence
        self._dependency_graph = dependency_graph
        self._estimated_cost = estimated_cost
        self._estimated_duration = estimated_duration
        self._success_criteria = success_criteria
        self._failure_policy = failure_policy
        self._retry_policy = retry_policy
        self._evaluation_requirements = evaluation_requirements
        self._expected_outcomes = expected_outcomes
        self._risk_level = risk_level
        self._confidence = confidence
        self._metadata = metadata
        self._status = status
        self._superseded_by = superseded_by
        self._timestamps = timestamps
        self._events: list[PlanningEvent] = []

    @classmethod
    def create(
        cls,
        target_id: EntityId,
        organization_id: EntityId,
        strategy: PlanningStrategy,
        sequence: AttackSequence,
        dependency_graph: AttackDependencyGraph,
        *,
        policy_id: EntityId | None = None,
        risk_appetite: RiskAppetite = RiskAppetite.BALANCED,
        estimated_cost: EstimatedCost | None = None,
        estimated_duration: EstimatedDuration | None = None,
        success_criteria: SuccessCriteria | None = None,
        failure_policy: FailureStrategy = FailureStrategy.FAIL_FAST,
        retry_policy: RetryPolicy | None = None,
        evaluation_requirements: frozenset[EvaluationRequirement] = frozenset(),
        expected_outcomes: frozenset[ExpectedOutcome] = frozenset(),
        risk_level: str = "medium",
        confidence: Confidence | None = None,
        metadata: dict[str, str] | None = None,
    ) -> Self:
        """Create a complete, immutable AttackPlan.

        Raises:
            EmptyPlanError: If `sequence` has zero steps.
        """
        if len(sequence) == 0:
            raise EmptyPlanError(str(target_id))

        plan = cls(
            id=EntityId.generate(),
            target_id=target_id,
            organization_id=organization_id,
            policy_id=policy_id,
            strategy=strategy,
            risk_appetite=risk_appetite,
            sequence=sequence,
            dependency_graph=dependency_graph,
            estimated_cost=estimated_cost or EstimatedCost(),
            estimated_duration=estimated_duration or EstimatedDuration(seconds=0),
            success_criteria=success_criteria or SuccessCriteria(
                description="At least one finding of medium severity or higher"
            ),
            failure_policy=failure_policy,
            retry_policy=retry_policy or RetryPolicy(),
            evaluation_requirements=evaluation_requirements,
            expected_outcomes=expected_outcomes,
            risk_level=risk_level,
            confidence=confidence or Confidence(score=0.5),
            metadata=metadata or {},
            status=PlanStatus.ACTIVE,
            superseded_by=None,
            timestamps=AuditTimestamps.create(),
        )
        plan._record_event(
            AttackPlanCreated(
                occurred_at=_now(),
                plan_id=str(plan._id),
                target_id=str(target_id),
                strategy=str(strategy),
                step_count=len(sequence),
            )
        )
        return plan

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def target_id(self) -> EntityId:
        return self._target_id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def policy_id(self) -> EntityId | None:
        return self._policy_id

    @property
    def strategy(self) -> PlanningStrategy:
        return self._strategy

    @property
    def risk_appetite(self) -> RiskAppetite:
        return self._risk_appetite

    @property
    def sequence(self) -> AttackSequence:
        return self._sequence

    @property
    def dependency_graph(self) -> AttackDependencyGraph:
        return self._dependency_graph

    @property
    def estimated_cost(self) -> EstimatedCost:
        return self._estimated_cost

    @property
    def estimated_duration(self) -> EstimatedDuration:
        return self._estimated_duration

    @property
    def success_criteria(self) -> SuccessCriteria:
        return self._success_criteria

    @property
    def failure_policy(self) -> FailureStrategy:
        return self._failure_policy

    @property
    def retry_policy(self) -> RetryPolicy:
        return self._retry_policy

    @property
    def evaluation_requirements(self) -> frozenset[EvaluationRequirement]:
        return frozenset(self._evaluation_requirements)

    @property
    def expected_outcomes(self) -> frozenset[ExpectedOutcome]:
        return frozenset(self._expected_outcomes)

    @property
    def risk_level(self) -> str:
        return self._risk_level

    @property
    def confidence(self) -> Confidence:
        return self._confidence

    @property
    def metadata(self) -> dict[str, str]:
        return dict(self._metadata)

    @property
    def status(self) -> PlanStatus:
        return self._status

    @property
    def superseded_by(self) -> EntityId | None:
        return self._superseded_by

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_active(self) -> bool:
        return self._status == PlanStatus.ACTIVE

    @property
    def attack_count(self) -> int:
        return len(self._sequence)

    # ─── Lifecycle ────────────────────────────────────────────────────────

    def supersede(self, new_plan_id: EntityId) -> None:
        """Mark this plan superseded by a newer plan (a replan).

        Raises:
            PlanAlreadySupersededError: If already superseded.
        """
        if self._status == PlanStatus.SUPERSEDED:
            raise PlanAlreadySupersededError(str(self._id))
        self._status = PlanStatus.SUPERSEDED
        self._superseded_by = new_plan_id
        self._touch()
        self._record_event(
            AttackPlanSuperseded(
                occurred_at=_now(),
                plan_id=str(self._id),
                superseded_by=str(new_plan_id),
            )
        )

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[PlanningEvent]:
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: PlanningEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AttackPlan):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"AttackPlan(id={self._id}, target_id={self._target_id}, "
            f"strategy={self._strategy}, steps={len(self._sequence)}, "
            f"status={self._status})"
        )
