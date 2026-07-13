"""Domain events for the Response Evaluation Intelligence bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class EvaluationEvent:
    """Base class for all Evaluation domain events."""

    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class EvaluationResultCreated(EvaluationEvent):
    """A new evaluation result was produced for an executed attack."""

    evaluation_id: str
    attack_id: str
    outcome: str
    confidence: float


@dataclass(frozen=True, slots=True)
class EvaluationResultSuperseded(EvaluationEvent):
    """An evaluation result was superseded by a re-evaluation."""

    evaluation_id: str
    superseded_by: str


def _now() -> datetime:
    return utc_now()
