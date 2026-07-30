"""Domain events emitted by the `EnterpriseRiskProfile` aggregate
(M48B)."""

from __future__ import annotations

from dataclasses import dataclass

from risk_engine.domain.events.base import BaseDomainEvent
from risk_engine.domain.value_objects.composite_score import CompositeRiskScore


@dataclass(frozen=True, slots=True)
class RiskProfileCreated(BaseDomainEvent):
    subject_reference: str = ""


@dataclass(frozen=True, slots=True)
class RiskProfileScoreRecomputed(BaseDomainEvent):
    composite_score: CompositeRiskScore | None = None
    contribution_count: int = 0


@dataclass(frozen=True, slots=True)
class RiskProfileStatusChanged(BaseDomainEvent):
    from_status: str = ""
    to_status: str = ""


@dataclass(frozen=True, slots=True)
class RiskProfileAcknowledged(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class RiskProfileMitigated(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class RiskProfileAccepted(BaseDomainEvent):
    expires_at: str = ""


@dataclass(frozen=True, slots=True)
class RiskProfileClosed(BaseDomainEvent):
    pass
