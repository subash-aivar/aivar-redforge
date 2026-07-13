"""Domain events for the Network Security bounded context (M16)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class NetworkSecurityEvent:
    """Base class for all Network Security domain events."""

    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class NetworkRunCreated(NetworkSecurityEvent):
    run_id: str
    organization_id: str
    target_asset_id: str


@dataclass(frozen=True, slots=True)
class NetworkRunPolicyDenied(NetworkSecurityEvent):
    run_id: str
    organization_id: str
    reason_code: str


@dataclass(frozen=True, slots=True)
class NetworkRunAuthorized(NetworkSecurityEvent):
    run_id: str
    organization_id: str
    authorization_id: str


@dataclass(frozen=True, slots=True)
class NetworkRunStarted(NetworkSecurityEvent):
    run_id: str
    organization_id: str


@dataclass(frozen=True, slots=True)
class NetworkRunFinished(NetworkSecurityEvent):
    run_id: str
    organization_id: str
    status: str
    payload: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class NetworkRunCancelled(NetworkSecurityEvent):
    run_id: str
    organization_id: str


@dataclass(frozen=True, slots=True)
class NetworkPolicyCreated(NetworkSecurityEvent):
    policy_id: str
    organization_id: str
    target_asset_id: str


@dataclass(frozen=True, slots=True)
class NetworkPolicyActivated(NetworkSecurityEvent):
    policy_id: str
    organization_id: str


@dataclass(frozen=True, slots=True)
class NetworkPolicyPaused(NetworkSecurityEvent):
    policy_id: str
    organization_id: str


@dataclass(frozen=True, slots=True)
class NetworkPolicyResumed(NetworkSecurityEvent):
    policy_id: str
    organization_id: str


@dataclass(frozen=True, slots=True)
class NetworkPolicyDisabled(NetworkSecurityEvent):
    policy_id: str
    organization_id: str


def _now() -> datetime:
    return utc_now()
