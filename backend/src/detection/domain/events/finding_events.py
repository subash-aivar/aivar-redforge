"""Domain events for DetectionFinding aggregate."""

from __future__ import annotations

from dataclasses import dataclass

from detection.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionFindingProduced(BaseDomainEvent):
    rule_id: str
    rule_version: str | None
    execution_id: str
    finding_key: str
    asset_id: str
    severity: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionFindingTriaged(BaseDomainEvent):
    analyst: str
    note: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionFindingConfirmed(BaseDomainEvent):
    analyst: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionFindingMarkedFalsePositive(BaseDomainEvent):
    analyst: str
    justification: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionFindingSuppressed(BaseDomainEvent):
    analyst: str
    justification: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionFindingEscalated(BaseDomainEvent):
    analyst: str
    investigation_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionFindingClosed(BaseDomainEvent):
    reason: str
