"""Domain events produced by the `CloudDiscoveryJob` aggregate (M45E).
Every event carries lifecycle/progress metadata only — never security
findings, risk scores, or compliance outcomes (explicitly out of scope
for this bounded context)."""

from __future__ import annotations

from dataclasses import dataclass

from cloud_security.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class DiscoveryJobStarted(BaseDomainEvent):
    account_id: str = ""
    provider_id: str = ""


@dataclass(frozen=True, slots=True)
class DiscoveryJobCompleted(BaseDomainEvent):
    discovered_count: int = 0
    updated_count: int = 0
    failed_count: int = 0


@dataclass(frozen=True, slots=True)
class DiscoveryJobFailed(BaseDomainEvent):
    reason: str = ""


@dataclass(frozen=True, slots=True)
class DiscoveryJobCancelled(BaseDomainEvent):
    pass
