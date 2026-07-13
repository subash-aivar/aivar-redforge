"""Domain events for the Continuous Validation bounded context (M14)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class ContinuousValidationEvent:
    """Base class for all Continuous Validation domain events."""

    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class PolicyCreated(ContinuousValidationEvent):
    policy_id: str
    organization_id: str
    target_id: str


@dataclass(frozen=True, slots=True)
class PolicyActivated(ContinuousValidationEvent):
    policy_id: str
    organization_id: str


@dataclass(frozen=True, slots=True)
class PolicyPaused(ContinuousValidationEvent):
    policy_id: str
    organization_id: str


@dataclass(frozen=True, slots=True)
class PolicyResumed(ContinuousValidationEvent):
    policy_id: str
    organization_id: str


@dataclass(frozen=True, slots=True)
class PolicyDisabled(ContinuousValidationEvent):
    policy_id: str
    organization_id: str


def _now() -> datetime:
    return utc_now()
