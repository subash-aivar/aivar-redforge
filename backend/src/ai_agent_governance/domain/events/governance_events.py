from __future__ import annotations

from dataclasses import dataclass

from ai_agent_governance.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class AgentOperationalEnvelopeDrafted(BaseDomainEvent):
    ai_system_asset_id: str
    envelope_version: int


@dataclass(frozen=True, slots=True)
class AgentOperationalEnvelopeApproved(BaseDomainEvent):
    approver_id: str
    envelope_version: int


@dataclass(frozen=True, slots=True)
class AgentOperationalEnvelopeRevised(BaseDomainEvent):
    previous_version: int
    new_version: int


@dataclass(frozen=True, slots=True)
class AgentOperationalEnvelopeSuspended(BaseDomainEvent):
    reason: str


@dataclass(frozen=True, slots=True)
class AgentOperationalEnvelopeRetired(BaseDomainEvent):
    reason: str


@dataclass(frozen=True, slots=True)
class AgentDeviationDetected(BaseDomainEvent):
    deviation_type: str
    severity: str
    envelope_version: int


@dataclass(frozen=True, slots=True)
class AgentDeviationReviewed(BaseDomainEvent):
    review_state: str


@dataclass(frozen=True, slots=True)
class AgentDeviationConfirmed(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class AgentDeviationDismissedBenign(BaseDomainEvent):
    notes: str
