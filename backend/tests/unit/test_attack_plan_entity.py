"""Unit tests for the AttackPlan aggregate root."""

from __future__ import annotations

import pytest

from redforge.domain.planning.entity import AttackPlan
from redforge.domain.planning.events import AttackPlanCreated, AttackPlanSuperseded
from redforge.domain.planning.exceptions import EmptyPlanError, PlanAlreadySupersededError
from redforge.domain.planning.value_objects import (
    AttackDependencyGraph,
    AttackPriority,
    AttackSequence,
    PlannedAttackStep,
    PlanningStrategy,
    PlanStatus,
    RiskAppetite,
)
from redforge.shared.identifiers import EntityId


def _sequence(n: int = 2) -> AttackSequence:
    steps = tuple(
        PlannedAttackStep(
            attack_id=EntityId.generate(), order=i, group="g",
            priority=AttackPriority.MEDIUM,
        )
        for i in range(n)
    )
    return AttackSequence(steps=steps)


def _plan(n: int = 2) -> AttackPlan:
    return AttackPlan.create(
        target_id=EntityId.generate(),
        organization_id=EntityId.generate(),
        strategy=PlanningStrategy.SINGLE_STEP,
        sequence=_sequence(n),
        dependency_graph=AttackDependencyGraph(),
    )


class TestCreate:
    def test_creates_active_plan(self) -> None:
        plan = _plan()
        assert plan.status == PlanStatus.ACTIVE
        assert plan.is_active is True

    def test_empty_sequence_raises(self) -> None:
        target_id = EntityId.generate()
        with pytest.raises(EmptyPlanError):
            AttackPlan.create(
                target_id=target_id,
                organization_id=EntityId.generate(),
                strategy=PlanningStrategy.SINGLE_STEP,
                sequence=AttackSequence(steps=()),
                dependency_graph=AttackDependencyGraph(),
            )

    def test_emits_created_event(self) -> None:
        plan = _plan(n=3)
        events = plan.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], AttackPlanCreated)
        assert events[0].step_count == 3

    def test_attack_count_matches_sequence(self) -> None:
        assert _plan(n=5).attack_count == 5

    def test_default_risk_appetite_is_balanced(self) -> None:
        assert _plan().risk_appetite == RiskAppetite.BALANCED

    def test_defaults_are_sane(self) -> None:
        plan = _plan()
        assert plan.policy_id is None
        assert plan.superseded_by is None
        assert plan.confidence.score == 0.5
        assert plan.estimated_cost.request_estimate == 0
        assert plan.success_criteria.description != ""

    def test_each_plan_gets_unique_id(self) -> None:
        assert _plan().id != _plan().id


class TestSupersede:
    def test_supersede_marks_superseded(self) -> None:
        plan = _plan()
        new_id = EntityId.generate()
        plan.supersede(new_id)
        assert plan.status == PlanStatus.SUPERSEDED
        assert plan.superseded_by == new_id
        assert plan.is_active is False

    def test_supersede_emits_event(self) -> None:
        plan = _plan()
        plan.collect_events()
        new_id = EntityId.generate()
        plan.supersede(new_id)
        events = plan.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], AttackPlanSuperseded)
        assert events[0].superseded_by == str(new_id)

    def test_double_supersede_raises(self) -> None:
        plan = _plan()
        plan.supersede(EntityId.generate())
        with pytest.raises(PlanAlreadySupersededError):
            plan.supersede(EntityId.generate())


class TestEquality:
    def test_same_id_equal(self) -> None:
        plan = _plan()
        other = AttackPlan(
            id=plan.id, target_id=EntityId.generate(), organization_id=EntityId.generate(),
            policy_id=None, strategy=PlanningStrategy.ESCALATION,
            risk_appetite=RiskAppetite.AGGRESSIVE, sequence=_sequence(1),
            dependency_graph=AttackDependencyGraph(),
            estimated_cost=plan.estimated_cost, estimated_duration=plan.estimated_duration,
            success_criteria=plan.success_criteria, failure_policy=plan.failure_policy,
            retry_policy=plan.retry_policy, evaluation_requirements=frozenset(),
            expected_outcomes=frozenset(), risk_level="low", confidence=plan.confidence,
            metadata={}, status=PlanStatus.SUPERSEDED, superseded_by=None,
            timestamps=plan.timestamps,
        )
        assert plan == other

    def test_different_id_not_equal(self) -> None:
        assert _plan() != _plan()

    def test_hashable(self) -> None:
        assert len({_plan(), _plan()}) == 2
