"""Domain events for the TargetAuthorization aggregate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from engagement.domain.events.base import BaseDomainEvent

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True, kw_only=True)
class TargetAuthorizationGranted(BaseDomainEvent):
    engagement_id: UUID
    asset_id: UUID
    impact_ceiling: str


@dataclass(frozen=True, slots=True, kw_only=True)
class TargetAuthorizationSuspended(BaseDomainEvent):
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class TargetAuthorizationRevoked(BaseDomainEvent):
    reason: str
    revoked_by: str


@dataclass(frozen=True, slots=True, kw_only=True)
class TargetAuthorizationExpired(BaseDomainEvent):
    pass
