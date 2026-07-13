"""Domain events for the Gated Safe Active Validation bounded context (M11)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class ValidationExecutionEvent:
    """Base class for all ValidationExecution domain events (collected
    for post-commit best-effort publishing — distinct from the
    persisted, immediately-visible `ExecutionEvent` live-progress log
    the application service writes incrementally; see entity.py's
    module docstring)."""

    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class ExecutionCreated(ValidationExecutionEvent):
    execution_id: str
    organization_id: str
    target_id: str


@dataclass(frozen=True, slots=True)
class ExecutionAuthorized(ValidationExecutionEvent):
    execution_id: str
    organization_id: str
    policy_decision_id: str


@dataclass(frozen=True, slots=True)
class ExecutionDenied(ValidationExecutionEvent):
    execution_id: str
    organization_id: str
    reason_code: str


@dataclass(frozen=True, slots=True)
class ExecutionStarted(ValidationExecutionEvent):
    execution_id: str
    organization_id: str


@dataclass(frozen=True, slots=True)
class ExecutionFinished(ValidationExecutionEvent):
    execution_id: str
    organization_id: str
    status: str


@dataclass(frozen=True, slots=True)
class ExecutionCancelled(ValidationExecutionEvent):
    execution_id: str
    organization_id: str


def _now() -> datetime:
    return utc_now()
