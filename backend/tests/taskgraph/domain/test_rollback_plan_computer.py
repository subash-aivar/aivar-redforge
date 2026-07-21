"""Unit tests for RollbackPlanComputer."""

from __future__ import annotations

from uuid import uuid4

from taskgraph.domain.services.rollback_plan_computer import RollbackPlanComputer


def test_compute_returns_eligible_in_reverse_order() -> None:
    a, b, c = uuid4(), uuid4(), uuid4()
    computer = RollbackPlanComputer()
    result = computer.compute([a, b, c], {a, c})
    assert result == [c, a]


def test_compute_empty_when_none_eligible() -> None:
    a, b = uuid4(), uuid4()
    computer = RollbackPlanComputer()
    assert computer.compute([a, b], set()) == []
