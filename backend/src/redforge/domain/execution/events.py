"""Domain events for the Execution Engine bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class ExecutionEvent:
    """Base class for all Execution Engine domain events."""

    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class PlanCreated(ExecutionEvent):
    """An execution plan was generated from a policy."""

    plan_id: str
    run_id: str
    policy_id: str
    stage_count: int
    total_steps: int


@dataclass(frozen=True, slots=True)
class PlanStarted(ExecutionEvent):
    """An execution plan began running."""

    plan_id: str


@dataclass(frozen=True, slots=True)
class PlanCompleted(ExecutionEvent):
    """An execution plan finished successfully."""

    plan_id: str
    steps_completed: int
    steps_failed: int


@dataclass(frozen=True, slots=True)
class PlanFailed(ExecutionEvent):
    """An execution plan terminated due to failure."""

    plan_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class PlanCancelled(ExecutionEvent):
    """An execution plan was cancelled."""

    plan_id: str


@dataclass(frozen=True, slots=True)
class StepCompleted(ExecutionEvent):
    """A single execution step finished."""

    plan_id: str
    step_id: str
    status: str
    evidence_id: str | None


def _now() -> datetime:
    return utc_now()
