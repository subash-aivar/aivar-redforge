"""Domain events for cloud risk."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class RiskDomainEvent:
    occurred_at: datetime
    organization_id: str
    risk_score_id: UUID


@dataclass(frozen=True, slots=True)
class RiskCalculated(RiskDomainEvent):
    cloud_asset_id: UUID
    overall_score: float
    calculation_version: str


@dataclass(frozen=True, slots=True)
class RiskUpdated(RiskDomainEvent):
    cloud_asset_id: UUID
    previous_score: float
    overall_score: float
    trend: str


@dataclass(frozen=True, slots=True)
class RiskSuppressed(RiskDomainEvent):
    reason: str
    suppressed_by: str


@dataclass(frozen=True, slots=True)
class RiskReopened(RiskDomainEvent):
    reason: str


@dataclass(frozen=True, slots=True)
class RiskThresholdExceeded(RiskDomainEvent):
    cloud_asset_id: UUID
    overall_score: float
    threshold: float


# Freeze-aligned aliases
CloudRiskScoreComputed = RiskCalculated
CloudRiskScoreCrossedThreshold = RiskThresholdExceeded


@dataclass(frozen=True, slots=True)
class CloudRiskScoreExpired(RiskDomainEvent):
    cloud_asset_id: UUID
    valid_until: datetime
