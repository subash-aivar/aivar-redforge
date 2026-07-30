"""Domain events emitted by the `NetworkRange` aggregate (M49A)."""

from __future__ import annotations

from dataclasses import dataclass

from attack_surface_management.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class NetworkRangeDiscovered(BaseDomainEvent):
    cidr: str = ""


@dataclass(frozen=True, slots=True)
class NetworkRangeAssetCountUpdated(BaseDomainEvent):
    previous_count: int = 0
    new_count: int = 0


@dataclass(frozen=True, slots=True)
class NetworkRangeActivated(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class NetworkRangeRetired(BaseDomainEvent):
    pass
