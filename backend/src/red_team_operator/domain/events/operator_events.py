"""Domain events raised by the RedTeamOperator aggregate."""

from __future__ import annotations

from dataclasses import dataclass

from red_team_operator.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class OperatorActivated(BaseDomainEvent):
    identity_ref: str
    clearance_level: str


@dataclass(frozen=True, slots=True, kw_only=True)
class OperatorSuspended(BaseDomainEvent):
    reason: str
    authority: str


@dataclass(frozen=True, slots=True, kw_only=True)
class OperatorRevoked(BaseDomainEvent):
    reason: str
    authority: str


@dataclass(frozen=True, slots=True, kw_only=True)
class OperatorClearanceLevelChanged(BaseDomainEvent):
    previous_level: str
    new_level: str
    authority: str


@dataclass(frozen=True, slots=True, kw_only=True)
class OperatorAddedToEngagement(BaseDomainEvent):
    engagement_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class OperatorRemovedFromEngagement(BaseDomainEvent):
    engagement_id: str
