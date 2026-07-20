"""Domain events for DetectionExecution aggregate."""

from __future__ import annotations

from dataclasses import dataclass

from detection.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionExecutionScheduled(BaseDomainEvent):
    rule_id: str
    rule_version: str | None
    source_id: str
    trigger: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionExecutionStarted(BaseDomainEvent):
    rule_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionExecutionCompleted(BaseDomainEvent):
    rule_id: str
    finding_count: int
    duration_ms: float


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionExecutionFailed(BaseDomainEvent):
    rule_id: str
    error_type: str
    error_message: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionExecutionTimedOut(BaseDomainEvent):
    rule_id: str
    duration_ms: float
