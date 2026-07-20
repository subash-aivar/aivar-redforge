"""Value objects for execution plans and steps."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class StepTechniqueRef:
    """Reference to a registered payload technique (cross-context string refs)."""

    payload_id: str
    technique_id: str

    def __post_init__(self) -> None:
        if not self.payload_id.strip():
            raise ValueError("payload_id must not be empty")
        if not self.technique_id.strip():
            raise ValueError("technique_id must not be empty")


@dataclass(frozen=True, slots=True)
class StepTargetRef:
    """Asset UUID within engagement TargetScope."""

    asset_id: UUID

    def __post_init__(self) -> None:
        if self.asset_id.int == 0:
            raise ValueError("asset_id must not be nil UUID")

    def __str__(self) -> str:
        return str(self.asset_id)


@dataclass(frozen=True, slots=True)
class StepConstraints:
    max_duration_seconds: int
    rollback_on_failure: bool
    continue_on_failure: bool

    def __post_init__(self) -> None:
        if self.max_duration_seconds <= 0:
            raise ValueError("max_duration_seconds must be positive")


@dataclass(frozen=True, slots=True)
class StepOutputRef:
    evidence_ref: str

    def __post_init__(self) -> None:
        if not self.evidence_ref.strip():
            raise ValueError("evidence_ref must not be empty")


@dataclass(frozen=True, slots=True)
class ExecutionWindowConstraint:
    """Allowed days (0=Mon..6=Sun) and hour range [start_hour, end_hour)."""

    allowed_days: tuple[int, ...]
    start_hour: int
    end_hour: int

    def __post_init__(self) -> None:
        if not self.allowed_days:
            raise ValueError("allowed_days must not be empty")
        for day in self.allowed_days:
            if day < 0 or day > 6:
                raise ValueError("allowed_days values must be 0-6")
        if not (0 <= self.start_hour <= 23):
            raise ValueError("start_hour must be 0-23")
        if not (1 <= self.end_hour <= 24):
            raise ValueError("end_hour must be 1-24")
        if self.start_hour >= self.end_hour:
            raise ValueError("start_hour must be < end_hour")

    def window_hours(self) -> int:
        return self.end_hour - self.start_hour


@dataclass(frozen=True, slots=True)
class RateLimit:
    max_executions: int
    window_seconds: int

    def __post_init__(self) -> None:
        if self.max_executions <= 0:
            raise ValueError("max_executions must be positive")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")


@dataclass(frozen=True, slots=True)
class MitreAttackRef:
    technique_id: str
    tactic: str | None = None

    def __post_init__(self) -> None:
        if not self.technique_id.strip():
            raise ValueError("technique_id must not be empty")


@dataclass(frozen=True, slots=True)
class PlanSnapshot:
    """Serialized JSON string representation of steps and dependencies."""

    value: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise ValueError("PlanSnapshot must not be empty")


@dataclass(frozen=True, slots=True)
class PlanHash:
    value: str

    def __post_init__(self) -> None:
        if len(self.value) != 64:
            raise ValueError("PlanHash must be a 64-char SHA-256 hex digest")

    @classmethod
    def from_snapshot(cls, snapshot: PlanSnapshot) -> PlanHash:
        digest = hashlib.sha256(snapshot.value.encode("utf-8")).hexdigest()
        return cls(digest)


@dataclass(frozen=True, slots=True)
class SignedBy:
    operator_id: UUID
    signed_at: datetime
    signature: str

    def __post_init__(self) -> None:
        if self.operator_id.int == 0:
            raise ValueError("operator_id must not be nil UUID")
        if not self.signature.strip():
            raise ValueError("signature must not be empty")
