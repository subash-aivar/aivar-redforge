"""Read-only, JSON-friendly DTOs for risk_engine's application layer
(M48C). Never expose a domain object — every field is a str/float/bool/
ISO-timestamp/tuple-of-primitives, rebuilt fresh from the aggregate
each time, mirroring `vulnerability_engine`'s `ScanTargetDTO`
convention."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class RiskContributionDTO:
    dimension: str
    normalized_score: float
    source_context: str
    source_id: str
    computed_at: datetime
    subject_reference: str | None = None


@dataclass(frozen=True, slots=True)
class EnterpriseRiskProfileDTO:
    profile_id: str
    tenant_id: str
    subject_reference: str
    status: str
    created_at: datetime
    updated_at: datetime
    composite_score: float | None = None
    weight_profile_id: str | None = None
    composite_computed_at: datetime | None = None
    accepted_expires_at: datetime | None = None
    contributions: tuple[RiskContributionDTO, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class RiskCorrelationDTO:
    correlation_set_id: str
    tenant_id: str
    formed_at: datetime
    signal_references: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class RiskScoreSnapshotDTO:
    """One point of a `RiskTimelineDTO`'s history — a flattened
    `CompositeRiskScore`."""

    value: float
    weight_profile_id: str
    computed_at: datetime


@dataclass(frozen=True, slots=True)
class RiskTimelineDTO:
    profile_id: str
    tenant_id: str
    snapshots: tuple[RiskScoreSnapshotDTO, ...]
    trend_direction: str
