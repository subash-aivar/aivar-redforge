"""Domain events for the Attack Planning & Strategy bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class PlanningEvent:
    """Base class for all Attack Planning domain events."""

    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class AttackPlanCreated(PlanningEvent):
    """A new attack plan was created for a target."""

    plan_id: str
    target_id: str
    strategy: str
    step_count: int


@dataclass(frozen=True, slots=True)
class AttackPlanSuperseded(PlanningEvent):
    """An attack plan was superseded by a newer plan (a replan)."""

    plan_id: str
    superseded_by: str


def _now() -> datetime:
    return utc_now()
