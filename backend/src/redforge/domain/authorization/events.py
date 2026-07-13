"""Domain events for the Security Authorization bounded context (M10)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class AuthorizationEvent:
    """Base class for all Security Authorization domain events."""

    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class AuthorizationCreated(AuthorizationEvent):
    authorization_id: str
    organization_id: str
    requester_user_id: str


@dataclass(frozen=True, slots=True)
class AuthorizationSubmittedForApproval(AuthorizationEvent):
    authorization_id: str
    organization_id: str


@dataclass(frozen=True, slots=True)
class AuthorizationApproved(AuthorizationEvent):
    authorization_id: str
    organization_id: str
    approver_user_id: str


@dataclass(frozen=True, slots=True)
class AuthorizationRejected(AuthorizationEvent):
    authorization_id: str
    organization_id: str
    approver_user_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class AuthorizationRevoked(AuthorizationEvent):
    authorization_id: str
    organization_id: str
    revoked_by_user_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class AuthorizationExpired(AuthorizationEvent):
    authorization_id: str
    organization_id: str


def _now() -> datetime:
    return utc_now()
