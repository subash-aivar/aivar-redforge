"""Domain events for the Engagement aggregate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from engagement.domain.events.base import BaseDomainEvent

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True, kw_only=True)
class EngagementCreated(BaseDomainEvent):
    classification: str
    owner_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class EngagementSubmittedForApproval(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class EngagementApprovalGranted(BaseDomainEvent):
    approver_id: str
    signature: str
    quorum_met: bool
    scope_hash: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class EngagementApprovalRevoked(BaseDomainEvent):
    approver_id: str
    revoked_by: str


@dataclass(frozen=True, slots=True, kw_only=True)
class EngagementActivated(BaseDomainEvent):
    scope_hash: str


@dataclass(frozen=True, slots=True, kw_only=True)
class EngagementSuspended(BaseDomainEvent):
    reason: str
    authority: str


@dataclass(frozen=True, slots=True, kw_only=True)
class EngagementClosed(BaseDomainEvent):
    reason: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class EngagementArchived(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class KillSwitchTriggered(BaseDomainEvent):
    authority: str
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class KillSwitchReleased(BaseDomainEvent):
    authority: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ScopeExpansionRequested(BaseDomainEvent):
    added_asset_ids: list[UUID]
    engagement_version: int


@dataclass(frozen=True, slots=True, kw_only=True)
class ScopeExpansionApproved(BaseDomainEvent):
    engagement_version: int
    scope_hash: str


@dataclass(frozen=True, slots=True, kw_only=True)
class RulesOfEngagementVersioned(BaseDomainEvent):
    roe_version: int
    signed: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class ParticipantAdded(BaseDomainEvent):
    operator_id: str
    role: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ParticipantRemoved(BaseDomainEvent):
    operator_id: str
