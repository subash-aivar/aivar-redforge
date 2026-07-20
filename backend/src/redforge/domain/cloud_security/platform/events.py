"""Domain events for M26 Phase 8 platform orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class PlatformDomainEvent:
    organization_id: str
    run_id: str
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class PlatformOrchestrationStarted(PlatformDomainEvent):
    scope: str
    target_id: str
    operation_id: str


@dataclass(frozen=True, slots=True)
class PlatformOrchestrationCompleted(PlatformDomainEvent):
    status: str
    steps_completed: int
    steps_failed: int


@dataclass(frozen=True, slots=True)
class PlatformOrchestrationStepFailed(PlatformDomainEvent):
    step_name: str
    error: str
